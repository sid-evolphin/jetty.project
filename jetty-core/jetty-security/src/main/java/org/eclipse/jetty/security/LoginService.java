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

package org.eclipse.jetty.security;

import java.util.function.Function;

import org.eclipse.jetty.server.Session;

/**
 * Login Service Interface.
 * <p>
 * The Login service provides an abstract mechanism for an {@link Authenticator}
 * to check credentials and to create a {@link UserIdentity} using the
 * set {@link IdentityService}.
 */
public interface LoginService
{

    /**
     * @return Get the name of the login service (aka Realm name)
     */
    String getName();

    /**
     * Login a user.
     *
     * @param username The username.
     * @param credentials The users credentials.
     * @param getSession function to retrieve or create a session.
     * @return A UserIdentity if the credentials matched, otherwise null
     */
    UserIdentity login(String username, Object credentials, Function<Boolean, Session> getSession);

    /**
     * Validate a user identity.
     * Validate that a UserIdentity previously created by a call
     * to {@link #login(String, Object, Function<Boolean, Session>)} is still valid.
     *
     * @param user The user to validate
     * @return true if authentication has not been revoked for the user.
     */
    boolean validate(UserIdentity user);

    /**
     * Get the IdentityService associated with this Login Service.
     *
     * @return the IdentityService associated with this Login Service.
     */
    IdentityService getIdentityService();

    /**
     * Set the IdentityService associated with this Login Service.
     *
     * @param service the IdentityService associated with this Login Service.
     */
    void setIdentityService(IdentityService service);

    void logout(UserIdentity user);
}