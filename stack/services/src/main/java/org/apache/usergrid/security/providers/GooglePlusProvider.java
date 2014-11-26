/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.usergrid.security.providers;


import java.util.LinkedHashMap;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.usergrid.management.ManagementService;
import org.apache.usergrid.persistence.EntityManager;
import org.apache.usergrid.persistence.Identifier;
import org.apache.usergrid.persistence.Query;
import org.apache.usergrid.persistence.Results;
import org.apache.usergrid.persistence.entities.User;
import org.apache.usergrid.security.tokens.exceptions.BadTokenException;
import org.apache.usergrid.utils.JsonUtils;

import static org.apache.usergrid.persistence.Schema.PROPERTY_MODIFIED;
import static org.apache.usergrid.utils.ListUtils.anyNull;


/**
 * Provider implementation for sign-in-as with Google+
 *
 * @author René Kilczan
 */
public class GooglePlusProvider extends AbstractProvider {
    private static final String API_URL = "https://www.googleapis.com/oauth2/v2/userinfo";
    private static final String TOKEN_URL = "https://www.googleapis.com/oauth2/v1/tokeninfo";

    private Logger logger = LoggerFactory.getLogger( GooglePlusProvider.class );

    private String issuedTo;

    GooglePlusProvider( EntityManager entityManager, ManagementService managementService ) {
        super( entityManager, managementService );
    }


    @Override
    void configure() {
        try {
            Map config = loadConfigurationFor( "googlePlusProvider" );
            if ( config != null ) {
                issuedTo = ( String ) config.get( "issued_to" );
            }
        }
        catch ( Exception ex ) {
            ex.printStackTrace();
        }
    }


    @Override
    public Map<Object, Object> loadConfigurationFor() {
        return loadConfigurationFor( "googlePlusProvider" );
    }


    /** Configuration parameters we look for: <ul> <li>issued_to</li> </ul> */
    @Override
    public void saveToConfiguration( Map<String, Object> config ) {
        saveToConfiguration( "googlePlusProvider", config );
    }


    @Override
    Map<String, Object> userFromResource( String externalToken ) {
        // TODO check if token belongs to our app
        // managementService.getProperties()
        return client.resource( API_URL ).header( "Authorization", "Bearer " + externalToken )
                     .accept( MediaType.APPLICATION_JSON ).get( Map.class );
    }


    @Override
    public User createOrAuthenticate( String externalToken ) throws BadTokenException {

        Map<String, Object> gp_user = userFromResource( externalToken );

        String gp_user_id = ( String ) gp_user.get( "id" );
        String gp_user_name = ( String ) gp_user.get( "name" );
        //String gp_user_username = ( String ) gp_user.get( "username" );
        String gp_picture = ( String ) gp_user.get( "picture" );
        String gp_user_email = ( String ) gp_user.get( "email" );
        if ( logger.isDebugEnabled() ) {
            logger.debug( JsonUtils.mapToFormattedJsonString( gp_user ) );
        }

        User user = null;

        if ( ( gp_user != null ) && !anyNull( gp_user_id, gp_user_name ) ) {

            Results r = null;
            try {
                r = entityManager.searchCollection( entityManager.getApplicationRef(), "users",
                        Query.findForProperty( "googleplus.id", gp_user_id ) );
            }
            catch ( Exception ex ) {
                throw new BadTokenException( "Could not lookup user for that Google+ ID", ex );
            }
            if ( r.size() > 1 ) {
                logger.error( "Multiple users for G+ ID: " + gp_user_id );
                throw new BadTokenException( "multiple users with same Google+ ID" );
            }

            if ( r.size() < 1 ) {
                Map<String, Object> properties = new LinkedHashMap<String, Object>();

                properties.put( "googleplus", gp_user );
                properties.put( "username", "gp_" + gp_user_id );
                properties.put( "name", gp_user_name );
                properties.put( "picture", gp_picture );

                if ( gp_user_email != null ) {
                    try {
                        user = managementService.getAppUserByIdentifier( entityManager.getApplication().getUuid(),
                                Identifier.fromEmail( gp_user_email ) );
                    }
                    catch ( Exception ex ) {
                        throw new BadTokenException(
                                "Could not find existing user for this applicaiton for email: " + gp_user_email, ex );
                    }
                    // if we found the user by email, unbind the properties from above
                    // that will conflict
                    // then update the user
                    if ( user != null ) {
                        properties.remove( "username" );
                        properties.remove( "name" );
                        try {
                            entityManager.updateProperties( user, properties );
                        }
                        catch ( Exception ex ) {
                            throw new BadTokenException( "Could not update user with new credentials", ex );
                        }
                        user.setProperty( PROPERTY_MODIFIED, properties.get( PROPERTY_MODIFIED ) );
                    }
                    else {
                        properties.put( "email", gp_user_email );
                    }
                }
                if ( user == null ) {
                    properties.put( "activated", true );
                    try {
                        user = entityManager.create( "user", User.class, properties );
                    }
                    catch ( Exception ex ) {
                        throw new BadTokenException( "Could not create user for that token", ex );
                    }
                }
            }
            else {
                user = ( User ) r.getEntity().toTypedEntity();
                Map<String, Object> properties = new LinkedHashMap<String, Object>();

                properties.put( "googleplus", gp_user );
                properties.put( "picture", gp_picture );
                try {
                    entityManager.updateProperties( user, properties );
                    user.setProperty( PROPERTY_MODIFIED, properties.get( PROPERTY_MODIFIED ) );
                    user.setProperty( "googleplus", gp_user );
                    user.setProperty( "picture", gp_picture );
                }
                catch ( Exception ex ) {
                    throw new BadTokenException( "Could not update user properties", ex );
                }
            }
        }
        else {
            throw new BadTokenException( "Unable to confirm Google+ access token" );
        }

        return user;
    }
}
