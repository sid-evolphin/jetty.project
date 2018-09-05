//
//  ========================================================================
//  Copyright (c) 1995-2018 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.deploy.providers;

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import org.eclipse.jetty.deploy.test.XmlConfiguredJetty;
import org.eclipse.jetty.toolchain.test.MavenTestingUtils;
import org.eclipse.jetty.toolchain.test.TestingDir;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

@Ignore("See issue #1200")
public class WebAppProviderTest
{
    @Rule
    public TestingDir testdir = new TestingDir();
    private static XmlConfiguredJetty jetty;
    private boolean symlinkSupported = false;
    
    @Before
    public void setupEnvironment() throws Exception
    {
        jetty = new XmlConfiguredJetty(testdir);
        jetty.addConfiguration("jetty.xml");
        jetty.addConfiguration("jetty-http.xml");
        jetty.addConfiguration("jetty-deploy-wars.xml");

        // Setup initial context
        jetty.copyWebapp("foo-webapp-1.war","foo.war");
        
        // Make symlink
        Path pathWar3 = MavenTestingUtils.getTestResourcePathFile("webapps/foo-webapp-3.war");
        Path pathBar = jetty.getJettyDir("webapps/bar.war").toPath();
        try
        {
            Files.createSymbolicLink(pathBar, pathWar3);
            symlinkSupported = true;
        } catch (UnsupportedOperationException | FileSystemException e)
        {
            // if unable to create symlink, no point testing that feature
            // this is the path that Microsoft Windows takes.
            symlinkSupported = false;
        }

        // Should not throw an Exception
        jetty.load();

        // Start it
        jetty.start();
    }

    @After
    public void teardownEnvironment() throws Exception
    {
        // Stop jetty.
        jetty.stop();
    }

    @Test
    public void testStartupContext()
    {
        // Check Server for Handlers
        jetty.assertWebAppContextsExists("/bar", "/foo");

        File workDir = jetty.getJettyDir("workish");

        // Test for regressions
        assertDirNotExists("root of work directory",workDir,"webinf");
        assertDirNotExists("root of work directory",workDir,"jsp");

        // Test for correct behaviour
        assertTrue("Should have generated directory in work directory: " + workDir,hasJettyGeneratedPath(workDir,"foo.war"));
    }
    
    @Test
    public void testStartupSymlinkContext()
    {
        assumeTrue(symlinkSupported);
        
        // Check for path
        File barLink = jetty.getJettyDir("webapps/bar.war");
        assertTrue("bar.war link exists: " + barLink.toString(), barLink.exists());
        assertTrue("bar.war link isFile: " + barLink.toString(), barLink.isFile());
        
        // Check Server for expected Handlers
        jetty.assertWebAppContextsExists("/bar", "/foo");
        
        // Test for expected work/temp directory behaviour
        File workDir = jetty.getJettyDir("workish");
        assertTrue("Should have generated directory in work directory: " + workDir,hasJettyGeneratedPath(workDir,"bar.war"));
    }

    private static boolean hasJettyGeneratedPath(File basedir, String expectedWarFilename)
    {
        File[] paths = basedir.listFiles();
        if (paths != null)
        {
            for (File path : paths)
            {
                if (path.exists() && path.isDirectory() && path.getName().startsWith("jetty-") && path.getName().contains(expectedWarFilename))
                {
                    System.err.println("Found expected generated directory: " + path);
                    return true;
                }
            }
            System.err.println("did not find "+expectedWarFilename+" in "+Arrays.asList(paths));
        }
        return false;
    }

    public static void assertDirNotExists(String msg, File workDir, String subdir)
    {
        File dir = new File(workDir,subdir);
        Assert.assertFalse("Should not have " + subdir + " in " + msg + " - " + workDir,dir.exists());
    }
}
