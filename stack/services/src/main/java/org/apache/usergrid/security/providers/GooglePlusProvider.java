/*
 * Copyright (c) 2014 TOMORROW FOCUS News+ GmbH. All rights reserved.
 *
 * This copyright will change soon to Apache 2.0, but for now this code is not official given back
 * to the community (juristic stuff).
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
 * @author René Kilczan (rene.kilczan@netmoms.de)
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
            String result = "";
            Properties prop = new Properties();
            String propFileName = "googleplus.properties";

            InputStream inputStream = getClass().getClassLoader().getResourceAsStream(propFileName);

            if (inputStream != null) {
                prop.load(inputStream);
            } else {
                throw new FileNotFoundException("property file '" + propFileName + "' not found in the classpath");
            }

            issuedTo = prop.getProperty("issued_to");
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
