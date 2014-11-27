/*
 * Copyright (c) 2014 TOMORROW FOCUS News+ GmbH. All rights reserved.
 *
 * This copyright will change soon to Apache 2.0, but for now this code is not official given back
 * to the community (juristic stuff).
 */
package org.apache.usergrid.security.providers;


import java.util.Map;
import java.util.UUID;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.apache.usergrid.ServiceITSetup;
import org.apache.usergrid.ServiceITSetupImpl;
import org.apache.usergrid.ServiceITSuite;
import org.apache.usergrid.cassandra.ClearShiroSubject;
import org.apache.usergrid.cassandra.Concurrent;
import org.apache.usergrid.management.OrganizationInfo;
import org.apache.usergrid.management.UserInfo;
import org.apache.usergrid.persistence.entities.Application;
import org.apache.usergrid.persistence.entities.User;
import org.apache.usergrid.utils.MapUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;


/**
 * Port of the FacebookProvider unit test for the Google+ Login.
 * 
 * @author René Kilczan (rene.kilczan@netmoms.de)
 */
@Concurrent()
public class GooglePlusProviderIT {

    private static SignInProviderFactory providerFactory;
    private static UUID applicationId;

    @Rule
    public ClearShiroSubject clearShiroSubject = new ClearShiroSubject();

    @ClassRule
    public static ServiceITSetup setup = new ServiceITSetupImpl( ServiceITSuite.cassandraResource );


    @BeforeClass
    public static void setup() throws Exception {
        providerFactory = ServiceITSuite.cassandraResource.getBean( SignInProviderFactory.class );
        UserInfo adminUser = setup.getMgmtSvc()
                                  .createAdminUser( "gpuser", "Google User", "user@gmail.com", "test", false,
                                          false );
        OrganizationInfo organization = setup.getMgmtSvc().createOrganization( "gp-organization", adminUser, true );
        applicationId = setup.getMgmtSvc().createApplication( organization.getUuid(), "gp-application" ).getId();
    }


    @Test
    @Ignore
    public void verifyGetOrCreateOk() throws Exception {
        Application application = setup.getEmf().getEntityManager( applicationId ).getApplication();
        Map gp_user = MapUtils.hashMap( "id", "12345678" ).map( "name", "Google User" ).map( "username", "gp.user" );

        GooglePlusProvider googlePlusProvider = ( GooglePlusProvider ) providerFactory.googleplus( application );

        String gp_access_token = "ya29.yQC...jTg";
        User user1 = googlePlusProvider.createOrAuthenticate( gp_access_token );

        assertNotNull( user1 );
    }


    @Test
    public void verifyConfigureOk() throws Exception {
        Application application = setup.getEmf().getEntityManager( applicationId ).getApplication();
        Map gpProps = MapUtils.hashMap( "api_url", "localhost" );
        GooglePlusProvider gp = ( GooglePlusProvider ) providerFactory.googleplus( application );
        assertNotNull( gp );

        gp.saveToConfiguration( "googleplusProvider", gpProps );

        gp.configure();

        Map map = gp.loadConfigurationFor( "googleplusProvider" );
        assertEquals( "localhost", map.get( "api_url" ) );
    }
}
