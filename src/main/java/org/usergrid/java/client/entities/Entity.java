package org.usergrid.java.client.entities;

import static org.usergrid.java.client.utils.JsonUtils.getStringProperty;
import static org.usergrid.java.client.utils.JsonUtils.getUUIDProperty;
import static org.usergrid.java.client.utils.JsonUtils.setStringProperty;
import static org.usergrid.java.client.utils.JsonUtils.*;
import static org.usergrid.java.client.utils.MapUtils.newMapWithoutKeys;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.annotate.JsonAnyGetter;
import org.codehaus.jackson.annotate.JsonAnySetter;
import org.codehaus.jackson.annotate.JsonIgnore;

public class Entity {

    public final static String PROPERTY_UUID = "uuid";
    public final static String PROPERTY_TYPE = "type";

    protected Map<String, JsonNode> properties = new HashMap<String, JsonNode>();

    public static Map<String, Class<? extends Entity>> CLASS_FOR_ENTITY_TYPE = new HashMap<String, Class<? extends Entity>>();
    static {
        CLASS_FOR_ENTITY_TYPE.put(User.ENTITY_TYPE, User.class);
    }

    public Entity() {
    }

    public Entity(String type) {
        setType(type);
    }

    @JsonIgnore
    public String getNativeType() {
        return getType();
    }

    @JsonIgnore
    public List<String> getPropertyNames() {
        List<String> properties = new ArrayList<String>();
        properties.add(PROPERTY_TYPE);
        properties.add(PROPERTY_UUID);
        return properties;
    }

    public String getType() {
        return getStringProperty(properties, PROPERTY_TYPE);
    }

    public void setType(String type) {
        setStringProperty(properties, PROPERTY_TYPE, type);
    }

    public UUID getUuid() {
        return getUUIDProperty(properties, PROPERTY_UUID);
    }

    public void setUuid(UUID uuid) {
        setUUIDProperty(properties, PROPERTY_UUID, uuid);
    }

    @JsonAnyGetter
    public Map<String, JsonNode> getProperties() {
        return newMapWithoutKeys(properties, getPropertyNames());
    }

    @JsonAnySetter
    public void setProperty(String name, JsonNode value) {
        if (value == null) {
            properties.remove(name);
        } else {
            properties.put(name, value);
        }
    }

  
    /**
     * Set the property
     * 
     * @param name
     * @param value
     */
    public void setProperty(String name, String value) {
        setStringProperty(properties, name, value);
    }

    /**
     * Set the property
     * 
     * @param name
     * @param value
     */
    public void setProperty(String name, boolean value) {
        setBooleanProperty(properties, name, value);
    }

    /**
     * Set the property
     * 
     * @param name
     * @param value
     */
    public void setProperty(String name, long value) {
        setLongProperty(properties, name, value);
    }

    /**
     * Set the property
     * 
     * @param name
     * @param value
     */
    public void setProperty(String name, int value) {
        setProperty(name, (long) value);
    }

    /**
     * Set the property
     * 
     * @param name
     * @param value
     */
    public void setProperty(String name, float value) {
        setFloatProperty(properties, name, value);
    }

    @Override
    public String toString() {
        return toJsonString(this);
    }

    public <T extends Entity> T toType(Class<T> t) {
        return toType(this, t);
    }

    public static <T extends Entity> T toType(Entity entity, Class<T> t) {
        if (entity == null) {
            return null;
        }
        T newEntity = null;
        if (entity.getClass().isAssignableFrom(t)) {
            try {
                newEntity = (t.newInstance());
                if ((newEntity.getNativeType() != null)
                        && newEntity.getNativeType().equals(entity.getType())) {
                    newEntity.properties = entity.properties;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return newEntity;
    }

    public static <T extends Entity> List<T> toType(List<Entity> entities,
            Class<T> t) {
        List<T> l = new ArrayList<T>(entities != null ? entities.size() : 0);
        if (entities != null) {
            for (Entity entity : entities) {
                T newEntity = entity.toType(t);
                if (newEntity != null) {
                    l.add(newEntity);
                }
            }
        }
        return l;
    }

}
