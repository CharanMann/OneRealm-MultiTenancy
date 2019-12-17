/*
 * Copyright © 2017 ForgeRock, AS.
 *
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Portions Copyrighted 2017 Charan Mann
 *
 * OpenAM-SAMLSP-updateDynamicUser: Created by Charan Mann on 4/27/17 , 9:39 AM.
 */

package com.sun.identity.saml2.plugins;

import com.sun.identity.plugin.datastore.DataStoreProviderException;
import com.sun.identity.saml2.assertion.*;
import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.key.KeyUtil;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.openam.utils.CollectionUtils;

import java.security.PrivateKey;
import java.util.*;

/**
 * This class extends {@link DefaultLibrarySPAccountMapper} to allow multiple attributes for auto federation
 */
public class AutoFedSPAccountMapper extends DefaultLibrarySPAccountMapper {

    /**
     * Default constructor
     */
    public AutoFedSPAccountMapper() {
        debug.message("AutoFedSPAccountMapper.constructor: ");
        role = SP;
    }

    private boolean isAutoFedEnabled(String realm, String entityID) {
        return Boolean.parseBoolean(getAttribute(realm, entityID, SAML2Constants.AUTO_FED_ENABLED));
    }

    private boolean useNameIDAsSPUserID(String realm, String entityID) {
        return Boolean.parseBoolean(getAttribute(realm, entityID, SAML2Constants.USE_NAMEID_AS_SP_USERID));
    }

    /**
     * Returns user mapping to auto federate attributes.
     *
     * @param realm Realm name.
     * @param entityID Hosted <code>EntityID</code>.
     * @param assertion <code>Assertion</code> from the identity provider.
     *
     * @return Auto federation mapped user from the assertion auto federation <code>AttributeStatement</code>. if the
     * statement does not have the auto federation attribute then the NameID value will be used if use NameID as SP user
     * ID is enabled, otherwise null.
     */
    protected String getAutoFedUser(String realm, String entityID, Assertion assertion, String decryptedNameID,
                                    Set<PrivateKey> decryptionKeys) throws SAML2Exception {
        if (!isAutoFedEnabled(realm, entityID)) {
            if (debug.messageEnabled()) {
                debug.message("DefaultLibrarySPAccountMapper.getAutoFedUser: Auto federation is disabled.");
            }
            return null;
        }

        String autoFedAttribute = getAttribute(realm, entityID, SAML2Constants.AUTO_FED_ATTRIBUTE);
        if (autoFedAttribute == null || autoFedAttribute.isEmpty()) {
            debug.error("DefaultLibrarySPAccountMapper.getAutoFedUser: " +
                    "Auto federation is enabled but the auto federation attribute is not configured.");
            return null;
        }

        if (debug.messageEnabled()) {
            debug.message("DefaultLibrarySPAccountMapper.getAutoFedUser: Auto federation attribute is set to: "
                    + autoFedAttribute);
        }

        Set<String> autoFedAttributeValue = null;
        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        if (attributeStatements == null || attributeStatements.isEmpty()) {
            if (debug.messageEnabled()) {
                debug.message("DefaultLibrarySPAccountMapper.getAutoFedUser: " +
                        "Assertion does not have any attribute statements.");
            }
        } else {
            for (AttributeStatement statement : attributeStatements) {
                autoFedAttributeValue = getAttribute(statement, autoFedAttribute, decryptionKeys);
                if (autoFedAttributeValue != null && !autoFedAttributeValue.isEmpty()) {
                    if (debug.messageEnabled()) {
                        debug.message("DefaultLibrarySPAccountMapper.getAutoFedUser: " +
                                "Found auto federation attribute value in Assertion: " + autoFedAttributeValue);
                    }
                    break;
                }
            }
        }

        if (autoFedAttributeValue == null || autoFedAttributeValue.isEmpty()) {
            if (debug.messageEnabled()) {
                debug.message("DefaultLibrarySPAccountMapper.getAutoFedUser: Auto federation attribute is not specified"
                        + " as an attribute.");
            }
            if (!useNameIDAsSPUserID(realm, entityID)) {
                if (debug.messageEnabled()) {
                    debug.message("DefaultLibrarySPAccountMapper.getAutoFedUser: NameID as SP UserID was not enabled "
                            + " and auto federation attribute " + autoFedAttribute + " was not found in the Assertion");
                }
                return null;
            } else {
                if (debug.messageEnabled()) {
                    debug.message("DefaultLibrarySPAccountMapper.getAutoFedUser: Trying now to autofederate with nameID"
                            + ", nameID =" + decryptedNameID);
                }
                autoFedAttributeValue = CollectionUtils.asSet(decryptedNameID);
            }
        }

        String autoFedMapAttribute = null;
        DefaultSPAttributeMapper attributeMapper = new DefaultSPAttributeMapper();
        Map<String, String> attributeMap = attributeMapper.getConfigAttributeMap(realm, entityID, SP);
        if (attributeMap == null || attributeMap.isEmpty()) {
            if(debug.messageEnabled()) {
                debug.message("DefaultLibrarySPAccountMapper.getAutoFedUser: attribute map is not configured.");
            }
        } else {
            autoFedMapAttribute = attributeMap.get(autoFedAttribute);
        }

        if (autoFedMapAttribute == null) {
            if (debug.messageEnabled()) {
                debug.message("DefaultLibrarySPAccountMapper.getAutoFedUser: " +
                        "Auto federation attribute map is not specified in config.");
            }
            // assume it is the same as the auto fed attribute name
            autoFedMapAttribute = autoFedAttribute;
        }

        try {
            Map<String, Set<String>> map = new HashMap<>(1);
            map.put(autoFedMapAttribute, autoFedAttributeValue);

            if (debug.messageEnabled()) {
                debug.message("DefaultLibrarySPAccountMapper.getAutoFedUser: Search map: " + map);
            }

            String userId = dsProvider.getUserID(realm, map);
            if (userId != null && !userId.isEmpty()) {
                return userId;
            } else {
                // check dynamic profile creation or ignore profile, if enabled,
                // return auto-federation attribute value as uid
                if (isDynamicalOrIgnoredProfile(realm)) {
                    if (debug.messageEnabled()) {
                        debug.message("DefaultLibrarySPAccountMapper: dynamical user creation or ignore profile " +
                                "enabled : uid=" + autoFedAttributeValue);
                    }
                    // return the first value as uid
                    return autoFedAttributeValue.iterator().next();
                }
            }
        } catch (DataStoreProviderException dse) {
            if (debug.warningEnabled()) {
                debug.warning("DefaultLibrarySPAccountMapper.getAutoFedUser: Datastore provider exception", dse);
            }
        }

        return null;
    }

    private Set<String> getAttribute(AttributeStatement statement, String attributeName,
                                     Set<PrivateKey> decryptionKeys) {
        if (debug.messageEnabled()) {
            debug.message("DefaultLibrarySPAccountMapper.getAttribute: attribute Name =" + attributeName);
        }

        // check it if the attribute needs to be encrypted?
        List<Attribute> list = statement.getAttribute();
        List<EncryptedAttribute> encList = statement.getEncryptedAttribute();
        if (encList != null && !encList.isEmpty()) {
            // a new list to hold the union of clear and encrypted attributes
            List<Attribute> allList = new ArrayList<>();
            if (list != null) {
                allList.addAll(list);
            }
            list = allList;
            for (EncryptedAttribute encryptedAttribute : encList) {
                try {
                    list.add(encryptedAttribute.decrypt(decryptionKeys));
                } catch (SAML2Exception se) {
                    debug.error("Decryption error:", se);
                    return null;
                }
            }
        }

        for (Attribute attribute : list) {
            if (!attributeName.equalsIgnoreCase(attribute.getName())) {
                continue;
            }

            List<String> values = attribute.getAttributeValueString();
            if (values == null || values.isEmpty()) {
                return null;
            }
            return new HashSet<>(values);
        }
        return null;
    }

}
