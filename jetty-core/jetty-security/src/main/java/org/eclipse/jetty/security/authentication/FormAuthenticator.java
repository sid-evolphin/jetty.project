//
// ========================================================================
// Copyright (c) 1995 Mort Bay Consulting Pty Ltd and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
// ========================================================================
//

package org.eclipse.jetty.security.authentication;

import java.util.concurrent.ExecutionException;

import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.http.HttpURI;
import org.eclipse.jetty.security.Authentication;
import org.eclipse.jetty.security.Authentication.User;
import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.Constraint;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.security.UserAuthentication;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.server.FormFields;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Session;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.Fields;
import org.eclipse.jetty.util.URIUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FORM Authenticator.
 *
 * <p>This authenticator implements form authentication will use dispatchers to
 * the login page if the {@link #__FORM_DISPATCH} init parameter is set to true.
 * Otherwise it will redirect.</p>
 *
 * <p>The form authenticator redirects unauthenticated requests to a log page
 * which should use a form to gather username/password from the user and send them
 * to the /j_security_check URI within the context.  FormAuthentication uses
 * {@link SessionAuthentication} to wrap Authentication results so that they
 * are  associated with the session.</p>
 */
public class FormAuthenticator extends LoginAuthenticator
{
    private static final Logger LOG = LoggerFactory.getLogger(FormAuthenticator.class);

    public static final String __FORM_LOGIN_PAGE = "org.eclipse.jetty.security.form_login_page";
    public static final String __FORM_ERROR_PAGE = "org.eclipse.jetty.security.form_error_page";
    public static final String __FORM_DISPATCH = "org.eclipse.jetty.security.dispatch";
    public static final String __J_URI = "org.eclipse.jetty.security.form_URI";
    public static final String __J_POST = "org.eclipse.jetty.security.form_POST";
    public static final String __J_METHOD = "org.eclipse.jetty.security.form_METHOD";
    public static final String __J_SECURITY_CHECK = "/j_security_check";
    public static final String __J_USERNAME = "j_username";
    public static final String __J_PASSWORD = "j_password";

    private String _formErrorPage;
    private String _formErrorPath;
    private String _formLoginPage;
    private String _formLoginPath;
    private boolean _dispatch;
    private boolean _alwaysSaveUri;

    public FormAuthenticator()
    {
    }

    public FormAuthenticator(String login, String error, boolean dispatch)
    {
        this();
        if (login != null)
            setLoginPage(login);
        if (error != null)
            setErrorPage(error);
        _dispatch = dispatch;
    }

    /**
     * If true, uris that cause a redirect to a login page will always
     * be remembered. If false, only the first uri that leads to a login
     * page redirect is remembered.
     * See https://bugs.eclipse.org/bugs/show_bug.cgi?id=379909
     *
     * @param alwaysSave true to always save the uri
     */
    public void setAlwaysSaveUri(boolean alwaysSave)
    {
        _alwaysSaveUri = alwaysSave;
    }

    public boolean getAlwaysSaveUri()
    {
        return _alwaysSaveUri;
    }

    @Override
    public void setConfiguration(AuthConfiguration configuration)
    {
        super.setConfiguration(configuration);
        String login = configuration.getParameter(FormAuthenticator.__FORM_LOGIN_PAGE);
        if (login != null)
            setLoginPage(login);
        String error = configuration.getParameter(FormAuthenticator.__FORM_ERROR_PAGE);
        if (error != null)
            setErrorPage(error);
        String dispatch = configuration.getParameter(FormAuthenticator.__FORM_DISPATCH);
        _dispatch = dispatch == null ? _dispatch : Boolean.parseBoolean(dispatch);
    }

    @Override
    public String getAuthMethod()
    {
        return Authenticator.FORM_AUTH;
    }

    private void setLoginPage(String path)
    {
        if (!path.startsWith("/"))
        {
            LOG.warn("form-login-page must start with /");
            path = "/" + path;
        }
        _formLoginPage = path;
        _formLoginPath = path;
        if (_formLoginPath.indexOf('?') > 0)
            _formLoginPath = _formLoginPath.substring(0, _formLoginPath.indexOf('?'));
    }

    private void setErrorPage(String path)
    {
        if (path == null || path.trim().length() == 0)
        {
            _formErrorPath = null;
            _formErrorPage = null;
        }
        else
        {
            if (!path.startsWith("/"))
            {
                LOG.warn("form-error-page must start with /");
                path = "/" + path;
            }
            _formErrorPage = path;
            _formErrorPath = path;

            if (_formErrorPath.indexOf('?') > 0)
                _formErrorPath = _formErrorPath.substring(0, _formErrorPath.indexOf('?'));
        }
    }

    @Override
    public UserIdentity login(String username, Object password, Request request, Response response)
    {
        UserIdentity user = super.login(username, password, request, response);
        if (user != null)
        {
            Session session = request.getSession(true);
            Authentication cached = new SessionAuthentication(getAuthMethod(), user, password);
            session.setAttribute(SessionAuthentication.AUTHENTICATED_ATTRIBUTE, cached);
        }
        return user;
    }

    @Override
    public void logout(Request request)
    {
        super.logout(request);
        Session session = request.getSession(false);
        if (session == null)
            return;

        //clean up session
        session.removeAttribute(SessionAuthentication.AUTHENTICATED_ATTRIBUTE);
    }

    @Override
    public Request prepareRequest(Request request, Authentication authentication)
    {
        // if this is a request resulting from a redirect after auth is complete
        // (ie its from a redirect to the original request uri) then due to
        // browser handling of 302 redirects, the method may not be the same as
        // that of the original request. Replace the method and original post
        // params (if it was a post).
        if (authentication instanceof Authentication.User user)
        {
            Session session = request.getSession(false);

            HttpURI juri = (HttpURI)session.getAttribute(__J_URI);
            HttpURI uri = request.getHttpURI();
            if ((uri.equals(juri)))
            {
                session.removeAttribute(__J_URI);

                Fields fields = (Fields)session.removeAttribute(__J_POST);
                if (fields != null)
                    request.setAttribute(FormFields.class.getName(), fields);

                String method = (String)session.removeAttribute(__J_METHOD);
                if (method != null && request.getMethod().equals(method))
                {
                    return new Request.Wrapper(request)
                    {
                        @Override
                        public String getMethod()
                        {
                            return method;
                        }
                    };
                }
            }
        }

        return request;
    }

    protected Fields getParameters(Request request)
    {
        try
        {
            Fields queryFields = Request.extractQueryParameters(request);
            Fields formFields = FormFields.from(request).get();
            return Fields.combine(queryFields, formFields);
        }
        catch (InterruptedException | ExecutionException e)
        {
            throw new RuntimeException(e);
        }
    }

    protected String encodeURL(String url)
    {
        // TODO
        return url;
    }

    @Override
    public Constraint.Authentication getConstraintAuthentication(String pathInContext, Constraint.Authentication existing)
    {
        if (isJSecurityCheck(pathInContext))
            return Constraint.Authentication.REQUIRE;
        if (isLoginOrErrorPage(pathInContext))
            return Constraint.Authentication.REQUIRE_NONE;
        return existing;
    }

    @Override
    public Authentication validateRequest(Request request, Response response, Callback callback) throws ServerAuthException
    {
        String pathInContext = Request.getPathInContext(request);
        boolean jSecurityCheck = isJSecurityCheck(pathInContext);

        // Handle a request for authentication.
        if (jSecurityCheck)
        {
            Fields parameters = getParameters(request);
            final String username = parameters.getValue(__J_USERNAME);
            final String password = parameters.getValue(__J_PASSWORD);

            UserIdentity user = login(username, password, request, response);
            LOG.debug("jsecuritycheck {} {}", username, user);
            if (user != null)
            {
                // Redirect to original request
                Session session = request.getSession(false);
                HttpURI savedURI = (HttpURI)session.getAttribute(__J_URI);
                String originalURI = savedURI != null ? savedURI.asString() : Request.getContextPath(request);
                if (originalURI == null)
                    originalURI = "/";
                FormAuthentication formAuth = new FormAuthentication(getAuthMethod(), user);
                Response.sendRedirect(request, response, callback, encodeURL(originalURI));
                return formAuth;
            }

            // not authenticated
            if (_formErrorPage == null)
                Response.writeError(request, response, callback, HttpStatus.FORBIDDEN_403);
            else
                Response.sendRedirect(request, response, callback, encodeURL(URIUtil.addPaths(request.getContext().getContextPath(), _formErrorPage)));

            return Authentication.SEND_FAILURE;
        }

        // Look for cached authentication
        Session session = request.getSession(false);
        Authentication authentication = session == null ? null : (Authentication)session.getAttribute(SessionAuthentication.AUTHENTICATED_ATTRIBUTE);
        if (LOG.isDebugEnabled())
            LOG.debug("auth {}", authentication);
        // Has authentication been revoked?
        if (authentication instanceof User user && _loginService != null && !_loginService.validate(user.getUserIdentity()))
        {
            if (LOG.isDebugEnabled())
                LOG.debug("auth revoked {}", authentication);
            session.removeAttribute(SessionAuthentication.AUTHENTICATED_ATTRIBUTE);
            authentication = null;
        }

        if (authentication != null)
            return authentication;

        // if we can't send challenge
        if (response.isCommitted())
        {
            LOG.debug("auth deferred {}", session == null ? null : session.getId());
            return null;
        }

        // remember the current URI
        session = (session != null ? session : request.getSession(true));
        synchronized (session)
        {
            // But only if it is not set already, or we save every uri that leads to a login form redirect
            if (session.getAttribute(__J_URI) == null || _alwaysSaveUri)
            {
                HttpURI juri = request.getHttpURI();
                session.setAttribute(__J_URI, juri);
                if (!HttpMethod.GET.is(request.getMethod()))
                    session.setAttribute(__J_METHOD, request.getMethod());

                if (HttpMethod.POST.is(request.getMethod()))
                {
                    try
                    {
                        session.setAttribute(__J_POST, FormFields.from(request).get());
                    }
                    catch (ExecutionException e)
                    {
                        throw new ServerAuthException(e.getCause());
                    }
                    catch (InterruptedException e)
                    {
                        throw new ServerAuthException(e);
                    }
                }
            }
        }

        // send the challenge
        if (LOG.isDebugEnabled())
            LOG.debug("challenge {}->{}", session.getId(), _formLoginPage);
        Response.sendRedirect(request, response, callback, encodeURL(URIUtil.addPaths(request.getContext().getContextPath(), _formLoginPage)));
        return Authentication.CHALLENGE;
    }

    public boolean isJSecurityCheck(String uri)
    {
        int jsc = uri.indexOf(__J_SECURITY_CHECK);

        if (jsc < 0)
            return false;
        int e = jsc + __J_SECURITY_CHECK.length();
        if (e == uri.length())
            return true;
        char c = uri.charAt(e);
        return c == ';' || c == '#' || c == '/' || c == '?';
    }

    public boolean isLoginOrErrorPage(String pathInContext)
    {
        return pathInContext != null && (pathInContext.equals(_formErrorPath) || pathInContext.equals(_formLoginPath));
    }

    /**
     * This Authentication represents a just completed Form authentication.
     * Subsequent requests from the same user are authenticated by the presence
     * of a {@link SessionAuthentication} instance in their session.
     */
    public static class FormAuthentication extends UserAuthentication implements Authentication.ResponseSent
    {
        public FormAuthentication(String method, UserIdentity userIdentity)
        {
            super(method, userIdentity);
        }

        @Override
        public String toString()
        {
            return "Form" + super.toString();
        }
    }
}
