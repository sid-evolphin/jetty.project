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

package org.eclipse.jetty.ee9.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;

import jakarta.servlet.HttpConstraintElement;
import jakarta.servlet.HttpMethodConstraintElement;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletSecurityElement;
import jakarta.servlet.annotation.ServletSecurity.EmptyRoleSemantic;
import jakarta.servlet.annotation.ServletSecurity.TransportGuarantee;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.jetty.ee.security.ConstraintAware;
import org.eclipse.jetty.ee.security.ConstraintMapping;
import org.eclipse.jetty.ee9.nested.ContextHandler;
import org.eclipse.jetty.ee9.nested.HandlerWrapper;
import org.eclipse.jetty.ee9.nested.Request;
import org.eclipse.jetty.http.pathmap.MappedResource;
import org.eclipse.jetty.http.pathmap.MatchedResource;
import org.eclipse.jetty.http.pathmap.PathMappings;
import org.eclipse.jetty.http.pathmap.PathSpec;
import org.eclipse.jetty.security.Constraint;
import org.eclipse.jetty.security.SecurityHandler;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.Blocker;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.component.DumpableCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ConstraintSecurityHandler
 * <p>
 * Handler to enforce SecurityConstraints. This implementation is servlet spec
 * 3.1 compliant and pre-computes the constraint combinations for runtime
 * efficiency.
 */
public class ConstraintSecurityHandler extends HandlerWrapper implements ConstraintAware
{
    private static final Logger LOG = LoggerFactory.getLogger(SecurityHandler.class); //use same as SecurityHandler

    public static final String ANY_ROLE = "*";
    public static final String ANY_AUTH = "**"; //Servlet Spec 3.1 pg 140
    private static final String OMISSION_SUFFIX = ".omission";
    private static final String ALL_METHODS = "*";
    private final SecurityHandler _securityHandler;
    private final List<ConstraintMapping> _constraintMappings = new CopyOnWriteArrayList<>();
    private final List<ConstraintMapping> _durableConstraintMappings = new CopyOnWriteArrayList<>();
    private final Set<String> _knownRoles = new CopyOnWriteArraySet<>();
    private final PathMappings<Map<String, Constraint>> _constraintRoles = new PathMappings<>();
    private boolean _denyUncoveredMethods = false;

    public ConstraintSecurityHandler()
    {
        _securityHandler = new SecurityHandler()
        {
            @Override
            protected Constraint getConstraint(String pathInContext, org.eclipse.jetty.server.Request request)
            {
                return ConstraintSecurityHandler.this.getConstraint(pathInContext, request);
            }

            @Override
            protected Set<String> getKnownRoles()
            {
                return _knownRoles;
            }
        };

        _securityHandler.setHandler(new Handler.Abstract()
        {
            @Override
            public boolean handle(org.eclipse.jetty.server.Request request, Response response, Callback callback) throws Exception
            {
                return false;
            }
        });
        addBean(_securityHandler);
    }

    @Override
    public void setServer(Server server)
    {
        super.setServer(server);
        _securityHandler.setServer(server);
    }

    @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
    {
        ContextHandler.CoreContextRequest coreRequest = baseRequest.getCoreRequest();
        Response coreResponse = baseRequest.getResponse().getHttpChannel().getCoreResponse();

        try (Blocker.Callback callback = Blocker.callback())
        {
            // TODO change API so that we do not need a callback?
            if (_securityHandler.handle(coreRequest, coreResponse, callback))
            {
                callback.block();
                baseRequest.setHandled(true);
                return;
            }
            callback.succeeded();
        }
        catch (IOException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new ServletException(e);
        }

        super.handle(target, baseRequest, request, response);
    }

    public static Constraint createConstraint()
    {
        return Constraint.NONE;
    }

    public static Constraint createConstraint(String name, Constraint.Authorization authorization, String[] roles, Constraint.UserData userData)
    {
        // TODO
        xxx;
        boolean anyRole = false;
        boolean anyAuth = false;
        if (roles != null)
        {
            for (int i = roles.length; i-- > 0; )
            {
                anyRole |= ANY_ROLE.equals(roles[i]);
                anyAuth |= ANY_AUTH.equals(roles[i]);
            }
        }

        return Constraint.from(name, false, userData, authorization, roles == null ? Collections.emptySet() : new HashSet<>(Arrays.asList(roles)));
    }

    /**
     * Create a Constraint
     *
     * @param name the name
     * @param element the http constraint element
     * @return the created constraint
     */
    public static Constraint createConstraint(String name, HttpConstraintElement element)
    {
        return createConstraint(name, element.getRolesAllowed(), element.getEmptyRoleSemantic(), element.getTransportGuarantee());
    }

    /**
     * Create Constraint
     *
     * @param name the name
     * @param rolesAllowed the list of allowed roles
     * @param permitOrDeny the permission semantic
     * @param transport the transport guarantee
     * @return the created constraint
     */
    public static Constraint createConstraint(String name, String[] rolesAllowed, EmptyRoleSemantic permitOrDeny, TransportGuarantee transport)
    {
        Constraint constraint = createConstraint();

        if (rolesAllowed == null || rolesAllowed.length == 0)
        {
            if (permitOrDeny.equals(EmptyRoleSemantic.DENY))
            {
                //Equivalent to <auth-constraint> with no roles
                constraint = constraint.named(name + "-Deny").with(Constraint.Authorization.AUTHENTICATED);
            }
            else
            {
                //Equivalent to no <auth-constraint>
                constraint = constraint.named(name + "-Permit").with(Constraint.Authorization.NONE);
            }
        }
        else
        {
            //Equivalent to <auth-constraint> with list of <security-role-name>s
            constraint.setAuthenticate(true);
            constraint.setRoles(rolesAllowed);
            constraint.setName(name + "-RolesAllowed");
        }

        //Equivalent to //<user-data-constraint><transport-guarantee>CONFIDENTIAL</transport-guarantee></user-data-constraint>
        constraint = constraint.with((transport.equals(TransportGuarantee.CONFIDENTIAL) ? Constraint.UserData.CONFIDENTIAL : Constraint.UserData.NONE));
        return constraint;
    }

    public static List<ConstraintMapping> getConstraintMappingsForPath(String pathSpec, List<ConstraintMapping> constraintMappings)
    {
        if (pathSpec == null || "".equals(pathSpec.trim()) || constraintMappings == null || constraintMappings.size() == 0)
            return Collections.emptyList();

        List<ConstraintMapping> mappings = new ArrayList<>();
        for (ConstraintMapping mapping : constraintMappings)
        {
            if (pathSpec.equals(mapping.getPathSpec()))
            {
                mappings.add(mapping);
            }
        }
        return mappings;
    }

    /**
     * Take out of the constraint mappings those that match the
     * given path.
     *
     * @param pathSpec the path spec
     * @param constraintMappings a new list minus the matching constraints
     * @return the list of constraint mappings
     */
    public static List<ConstraintMapping> removeConstraintMappingsForPath(String pathSpec, List<ConstraintMapping> constraintMappings)
    {
        if (pathSpec == null || "".equals(pathSpec.trim()) || constraintMappings == null || constraintMappings.size() == 0)
            return Collections.emptyList();

        List<ConstraintMapping> mappings = new ArrayList<>();
        for (ConstraintMapping mapping : constraintMappings)
        {
            //Remove the matching mappings by only copying in non-matching mappings
            if (!pathSpec.equals(mapping.getPathSpec()))
            {
                mappings.add(mapping);
            }
        }
        return mappings;
    }

    /**
     * Generate Constraints and ContraintMappings for the given url pattern and ServletSecurityElement
     *
     * @param name the name
     * @param pathSpec the path spec
     * @param securityElement the servlet security element
     * @return the list of constraint mappings
     */
    public static List<ConstraintMapping> createConstraintsWithMappingsForPath(String name, String pathSpec, ServletSecurityElement securityElement)
    {
        List<ConstraintMapping> mappings = new ArrayList<>();

        //Create a constraint that will describe the default case (ie if not overridden by specific HttpMethodConstraints)
        Constraint httpConstraint;
        ConstraintMapping httpConstraintMapping = null;

        if (securityElement.getEmptyRoleSemantic() != EmptyRoleSemantic.PERMIT ||
            securityElement.getRolesAllowed().length != 0 ||
            securityElement.getTransportGuarantee() != TransportGuarantee.NONE)
        {
            httpConstraint = ConstraintSecurityHandler.createConstraint(name, securityElement);

            //Create a mapping for the pathSpec for the default case
            httpConstraintMapping = new ConstraintMapping();
            httpConstraintMapping.setPathSpec(pathSpec);
            httpConstraintMapping.setConstraint(httpConstraint);
            mappings.add(httpConstraintMapping);
        }

        //See Spec 13.4.1.2 p127
        List<String> methodOmissions = new ArrayList<>();

        //make constraint mappings for this url for each of the HttpMethodConstraintElements
        java.util.Collection<HttpMethodConstraintElement> methodConstraintElements = securityElement.getHttpMethodConstraints();
        if (methodConstraintElements != null)
        {
            for (HttpMethodConstraintElement methodConstraintElement : methodConstraintElements)
            {
                //Make a Constraint that captures the <auth-constraint> and <user-data-constraint> elements supplied for the HttpMethodConstraintElement
                Constraint methodConstraint = ConstraintSecurityHandler.createConstraint(name, methodConstraintElement);
                ConstraintMapping mapping = new ConstraintMapping();
                mapping.setConstraint(methodConstraint);
                mapping.setPathSpec(pathSpec);
                if (methodConstraintElement.getMethodName() != null)
                {
                    mapping.setMethod(methodConstraintElement.getMethodName());
                    //See spec 13.4.1.2 p127 - add an omission for every method name to the default constraint
                    methodOmissions.add(methodConstraintElement.getMethodName());
                }
                mappings.add(mapping);
            }
        }
        //See spec 13.4.1.2 p127 - add an omission for every method name to the default constraint
        //UNLESS the default constraint contains all default values. In that case, we won't add it. See Servlet Spec 3.1 pg 129
        if (methodOmissions.size() > 0 && httpConstraintMapping != null)
            httpConstraintMapping.setMethodOmissions(methodOmissions.toArray(new String[0]));

        return mappings;
    }

    @Override
    public List<ConstraintMapping> getConstraintMappings()
    {
        return _constraintMappings;
    }

    @Override
    public Set<String> getKnownRoles()
    {
        return _knownRoles;
    }

    /**
     * Process the constraints following the combining rules in Servlet 3.0 EA
     * spec section 13.7.1 Note that much of the logic is in the Constraint class.
     *
     * @param constraintMappings The constraintMappings to set, from which the set of known roles
     * is determined.
     */
    public void setConstraintMappings(List<ConstraintMapping> constraintMappings)
    {
        setConstraintMappings(constraintMappings, null);
    }

    /**
     * Process the constraints following the combining rules in Servlet 3.0 EA
     * spec section 13.7.1 Note that much of the logic is in the Constraint class.
     *
     * @param constraintMappings The constraintMappings to set as array, from which the set of known roles
     * is determined.  Needed to retain API compatibility for 7.x
     */
    public void setConstraintMappings(ConstraintMapping[] constraintMappings)
    {
        setConstraintMappings(Arrays.asList(constraintMappings), null);
    }

    /**
     * Process the constraints following the combining rules in Servlet 3.0 EA
     * spec section 13.7.1 Note that much of the logic is in the Constraint class.
     *
     * @param constraintMappings The constraintMappings to set.
     * @param roles The known roles (or null to determine them from the mappings)
     */
    @Override
    public void setConstraintMappings(List<ConstraintMapping> constraintMappings, Set<String> roles)
    {
        _constraintMappings.clear();
        _constraintMappings.addAll(constraintMappings);

        _durableConstraintMappings.clear();
        if (isInDurableState())
        {
            _durableConstraintMappings.addAll(constraintMappings);
        }

        if (roles == null)
        {
            roles = new HashSet<>();
            for (ConstraintMapping cm : constraintMappings)
            {
                Set<String> cmr = cm.getConstraint().getRoles();
                if (cmr != null)
                {
                    for (String r : cmr)
                    {
                        if (!ALL_METHODS.equals(r))
                            roles.add(r);
                    }
                }
            }
        }
        setKnownRoles(roles);

        if (isStarted())
        {
            _constraintMappings.forEach(this::processConstraintMapping);
        }
    }

    /**
     * Set the known roles.
     * This may be overridden by a subsequent call to {@link #setConstraintMappings(ConstraintMapping[])} or
     * {@link #setConstraintMappings(List, Set)}.
     *
     * @param knownRoles The known roles (or null to determine them from the mappings)
     */
    public void setKnownRoles(Set<String> knownRoles)
    {
        _knownRoles.clear();
        _knownRoles.addAll(knownRoles);
    }

    @Override
    public void addConstraintMapping(ConstraintMapping mapping)
    {
        _constraintMappings.add(mapping);

        if (isInDurableState())
            _durableConstraintMappings.add(mapping);

        if (mapping.getConstraint() != null && mapping.getConstraint().getRoles() != null)
        {
            //allow for lazy role naming: if a role is named in a security constraint, try and
            //add it to the list of declared roles (ie as if it was declared with a security-role
            for (String role : mapping.getConstraint().getRoles())
            {
                if ("*".equals(role) || "**".equals(role))
                    continue;
                addKnownRole(role);
            }
        }

        if (isStarted())
            processConstraintMapping(mapping);
    }

    @Override
    public void addKnownRole(String role)
    {
        //add to list of declared roles
        boolean modified = _knownRoles.add(role);
        if (isStarted() && modified)
        {
            // Add the new role to currently defined any role role infos
            for (MappedResource<Map<String, Constraint>> map : _constraintRoles)
            {
                for (Constraint constraint : map.getResource().values())
                {
                    if (constraint.isAnyRole())
                        constraint.addRole(role);
                }
            }
        }
    }

    @Override
    protected void doStart() throws Exception
    {
        _constraintRoles.reset();
        _constraintMappings.forEach(this::processConstraintMapping);

        //Servlet Spec 3.1 pg 147 sec 13.8.4.2 log paths for which there are uncovered http methods
        checkPathsWithUncoveredHttpMethods();

        super.doStart();
    }

    @Override
    protected void doStop() throws Exception
    {
        super.doStop();
        _constraintRoles.reset();
        _constraintMappings.clear();
        _constraintMappings.addAll(_durableConstraintMappings);
    }

    /**
     * Create and combine the constraint with the existing processed
     * constraints.
     *
     * @param mapping the constraint mapping
     */
    protected void processConstraintMapping(ConstraintMapping mapping)
    {
        // Look for a method2Constraint mapping for the exact pathSpec
        Map<String, Constraint> method2Constraint = _constraintRoles.get(asPathSpec(mapping));
        if (method2Constraint == null)
        {
            method2Constraint = new HashMap<>();
            _constraintRoles.put(mapping.getPathSpec(), method2Constraint);
        }

        // If we already forbid all methods, then we do not need to add the mapping.
        Constraint allMethodsConstraint = method2Constraint.get(ALL_METHODS);
        if (allMethodsConstraint != null && allMethodsConstraint.isForbidden())
            return;

        // process omitted methods
        if (mapping.getMethodOmissions() != null && mapping.getMethodOmissions().length > 0)
        {
            processConstraintMappingWithMethodOmissions(mapping, method2Constraint);
            return;
        }

        // Get the method and if none specified, then it is applicable to all methods
        String httpMethod = mapping.getMethod();
        if (httpMethod == null)
            httpMethod = ALL_METHODS;
        Constraint constraint = method2Constraint.get(httpMethod);
        if (constraint == null)
        {
            constraint = new Constraint();
            method2Constraint.put(httpMethod, constraint);
            if (allMethodsConstraint != null)
            {
                constraint.combine(allMethodsConstraint);
            }
        }
        if (constraint.isForbidden())
            return;

        //add in info from the constraint
        configureConstraint(constraint, mapping);

        if (constraint.isForbidden())
        {
            if (httpMethod.equals(ALL_METHODS))
            {
                method2Constraint.clear();
                method2Constraint.put(ALL_METHODS, constraint);
            }
        }
    }

    protected PathSpec asPathSpec(ConstraintMapping mapping)
    {
        // As currently written, this allows regex patterns to be used.
        // This may not be supported by default in future releases.
        return PathSpec.from(mapping.getPathSpec());
    }

    /**
     * Constraints that name method omissions are dealt with differently.
     * We create an entry in the mappings with key "&lt;method&gt;.omission". This entry
     * is only ever combined with other omissions for the same method to produce a
     * consolidated Constraint. Then, when we wish to find the relevant constraints for
     * a given Request (in prepareConstraintInfo()), we consult 3 types of entries in
     * the mappings: an entry that names the method of the Request specifically, an
     * entry that names constraints that apply to all methods, entries of the form
     * &lt;method&gt;.omission, where the method of the Request is not named in the omission.
     *
     * @param mapping the constraint mapping
     * @param mappings the mappings of roles
     */
    protected void processConstraintMappingWithMethodOmissions(ConstraintMapping mapping, Map<String, Constraint> mappings)
    {
        String[] omissions = mapping.getMethodOmissions();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < omissions.length; i++)
        {
            if (i > 0)
                sb.append(".");
            sb.append(omissions[i]);
        }
        sb.append(OMISSION_SUFFIX);
        Constraint ri = new Constraint();
        mappings.put(sb.toString(), ri);
        configureConstraint(ri, mapping);
    }

    /**
     * Initialize or update the Constraint from the constraint
     *
     * @param ri the role info
     * @param mapping the constraint mapping
     */
    protected void configureConstraint(Constraint ri, ConstraintMapping mapping)
    {
        Constraint constraint = mapping.getConstraint();
        boolean forbidden = constraint.isForbidden();
        ri.setForbidden(forbidden);

        //set up the data constraint (NOTE: must be done after setForbidden, as it nulls out the data constraint
        //which we need in order to do combining of omissions in prepareConstraintInfo
        Constraint.UserData userDataConstraint = UserDataConstraint.get(mapping.getConstraint().getUserData());
        ri.setUserDataConstraint(userDataConstraint);

        //if forbidden, no point setting up roles
        if (!ri.isForbidden())
        {
            //add in the roles
            boolean checked = mapping.getConstraint().getAuthenticate();
            ri.setChecked(checked);

            if (ri.isChecked())
            {
                if (mapping.getConstraint().isAnyRole())
                {
                    // * means matches any defined role
                    for (String role : _knownRoles)
                    {
                        ri.addRole(role);
                    }
                    ri.setAnyRole(true);
                }
                else if (mapping.getConstraint().isAnyAuth())
                {
                    //being authenticated is sufficient, not necessary to check roles
                    ri.setAnyAuth(true);
                }
                else
                {
                    //user must be in one of the named roles
                    String[] newRoles = mapping.getConstraint().getRoles();
                    for (String role : newRoles)
                    {
                        //check role has been defined
                        if (!_knownRoles.contains(role))
                            throw new IllegalArgumentException("Attempt to use undeclared role: " + role + ", known roles: " + _knownRoles);
                        ri.addRole(role);
                    }
                }
            }
        }
    }

    /**
     * Find constraints that apply to the given path.
     * In order to do this, we consult 3 different types of information stored in the mappings for each path - each mapping
     * represents a merged set of user data constraints, roles etc -:
     * <ol>
     * <li>A mapping of an exact method name </li>
     * <li>A mapping with key * that matches every method name</li>
     * <li>Mappings with keys of the form "&lt;method&gt;.&lt;method&gt;.&lt;method&gt;.omission" that indicates it will match every method name EXCEPT those given</li>
     * </ol>
     *
     * @see SecurityHandler#prepareConstraintInfo(java.lang.String, Request)
     */
    protected Constraint getConstraint(String pathInContext, org.eclipse.jetty.server.Request request)
    {
        MatchedResource<Map<String, Constraint>> resource = _constraintRoles.getMatched(pathInContext);
        if (resource == null)
            return null;

        Map<String, Constraint> method2ConstraintMap = resource.getResource();
        if (method2ConstraintMap == null)
            return null;

        String httpMethod = request.getMethod();
        Constraint constraint = method2ConstraintMap.get(httpMethod);
        if (constraint == null)
        {
            //Get info for constraint that matches all methods if it exists
            constraint = method2ConstraintMap.get(ALL_METHODS);

            //Get info for constraints that name method omissions where target method name is not omitted
            //(ie matches because target method is not omitted, hence considered covered by the constraint)
            for (Map.Entry<String, Constraint> entry : method2ConstraintMap.entrySet())
            {
                if (entry.getKey() != null && entry.getKey().endsWith(OMISSION_SUFFIX) && !entry.getKey().contains(httpMethod))
                    constraint = Constraint.combine(constraint, entry.getValue());
            }

            if (constraint == null)
                constraint = isDenyUncoveredHttpMethods() ? Constraint.FORBIDDEN : Constraint.NONE;
        }

        return constraint;
    }

    @Override
    public void dump(Appendable out, String indent) throws IOException
    {
        dumpObjects(out, indent,
                    DumpableCollection.from("roles", _knownRoles),
                    DumpableCollection.from("constraints", _constraintMappings));
    }

    @Override
    public void setDenyUncoveredHttpMethods(boolean deny)
    {
        _denyUncoveredMethods = deny;
    }

    @Override
    public boolean isDenyUncoveredHttpMethods()
    {
        return _denyUncoveredMethods;
    }

    /**
     * Servlet spec 3.1 pg. 147.
     */
    @Override
    public boolean checkPathsWithUncoveredHttpMethods()
    {
        Set<String> paths = getPathsWithUncoveredHttpMethods();
        if (paths != null && !paths.isEmpty())
        {
            LOG.warn("{} has uncovered HTTP methods for the following paths: {}",
                ContextHandler.getCurrentContext(), paths);
            return true;
        }
        return false;
    }

    /**
     * Servlet spec 3.1 pg. 147.
     * The container must check all the combined security constraint
     * information and log any methods that are not protected and the
     * urls at which they are not protected
     *
     * @return A Set of paths for which there are uncovered methods
     */
    public Set<String> getPathsWithUncoveredHttpMethods()
    {
        //if automatically denying uncovered methods, there are no uncovered methods
        if (_denyUncoveredMethods)
            return Collections.emptySet();

        Set<String> uncoveredPaths = new HashSet<>();

        for (MappedResource<Map<String, Constraint>> resource : _constraintRoles)
        {
            String path = resource.getPathSpec().getDeclaration();
            Map<String, Constraint> methodMappings = resource.getResource();
            //Each key is either:
            // : an exact method name
            // : * which means that the constraint applies to every method
            // : a name of the form <method>.<method>.<method>.omission, which means it applies to every method EXCEPT those named
            if (methodMappings.get(ALL_METHODS) != null)
                continue; //can't be any uncovered methods for this url path

            boolean hasOmissions = omissionsExist(path, methodMappings);

            for (String method : methodMappings.keySet())
            {
                if (method.endsWith(OMISSION_SUFFIX))
                {
                    Set<String> omittedMethods = getOmittedMethods(method);
                    for (String m : omittedMethods)
                    {
                        if (!methodMappings.containsKey(m))
                            uncoveredPaths.add(path);
                    }
                }
                else
                {
                    //an exact method name
                    if (!hasOmissions)
                        //an http-method does not have http-method-omission to cover the other method names
                        uncoveredPaths.add(path);
                }
            }
        }
        return uncoveredPaths;
    }

    /**
     * Check if any http method omissions exist in the list of method
     * to auth info mappings.
     *
     * @param path the path
     * @param methodMappings the method mappings
     * @return true if omission exist
     */
    protected boolean omissionsExist(String path, Map<String, Constraint> methodMappings)
    {
        if (methodMappings == null)
            return false;
        boolean hasOmissions = false;
        for (String m : methodMappings.keySet())
        {
            if (m.endsWith(OMISSION_SUFFIX))
            {
                hasOmissions = true;
                break;
            }
        }
        return hasOmissions;
    }

    /**
     * Given a string of the form <code>&lt;method&gt;.&lt;method&gt;.omission</code>
     * split out the individual method names.
     *
     * @param omission the method
     * @return the list of strings
     */
    protected Set<String> getOmittedMethods(String omission)
    {
        if (omission == null || !omission.endsWith(OMISSION_SUFFIX))
            return Collections.emptySet();

        String[] strings = omission.split("\\.");
        Set<String> methods = new HashSet<>();
        for (int i = 0; i < strings.length - 1; i++)
        {
            methods.add(strings[i]);
        }
        return methods;
    }

    /**
     * Constraints can be added to the ConstraintSecurityHandler before the
     * associated context is started. These constraints should persist across
     * a stop/start. Others can be added after the associated context is starting
     * (eg by a web.xml/web-fragment.xml, annotation or jakarta.servlet api call) -
     * these should not be persisted across a stop/start as they will be re-added on
     * the restart.
     *
     * @return true if the context with which this ConstraintSecurityHandler
     * has not yet started, or if there is no context, the server has not yet started.
     */
    private boolean isInDurableState()
    {
        ContextHandler context = ContextHandler.getContextHandler(null);
        Server server = getServer();

        return (context == null && server == null) || (context != null && !context.isRunning()) || (context == null && server != null && !server.isRunning());
    }
}
