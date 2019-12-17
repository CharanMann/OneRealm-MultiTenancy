/*
 * Copyright © 2019 ForgeRock, AS.
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
 * Portions Copyrighted 2019 Charan Mann
 *
 * OneRealm-MultiTenancy: Created by Charan Mann on 12/17/19 , 11:38 AM.
 */

package com.sun.identity.saml2.plugins;

import com.sun.identity.plugin.datastore.DataStoreProviderException;
import com.sun.identity.saml2.assertion.Assertion;
import com.sun.identity.saml2.assertion.Attribute;
import com.sun.identity.saml2.assertion.AttributeStatement;
import com.sun.identity.saml2.assertion.EncryptedAttribute;
import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.common.SAML2Exception;

import java.security.PrivateKey;
import java.util.*;

/**
 * This class extends {@link AutoFedSPAccountMapper} to allow multiple attributes for auto federation.
 * <p>
 * Note: this extension removes some of the features also:
 * <p>
 * 1. This extension doesn't leverage NameID if auto federate attributes are not present.
 * 2. Doesn't perform dynamic profile creation as UID is random GUID in this usage.
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

    /**
     * Returns user mapping to auto federate attributes.
     *
     * @param realm     Realm name.
     * @param entityID  Hosted <code>EntityID</code>.
     * @param assertion <code>Assertion</code> from the identity provider.
     * @return Auto federation mapped user from the assertion auto federation <code>AttributeStatement</code>. if the
     * statement does not have the auto federation attribute then the NameID value will be used if use NameID as SP user
     * ID is enabled, otherwise null.
     */
    protected String getAutoFedUser(String realm, String entityID, Assertion assertion, String decryptedNameID,
                                    Set<PrivateKey> decryptionKeys) throws SAML2Exception {
        if (!isAutoFedEnabled(realm, entityID)) {
            if (debug.messageEnabled()) {
                debug.message("AutoFedSPAccountMapper.getAutoFedUser: Auto federation is disabled.");
            }
            return null;
        }

        String autoFedAttributes = getAttribute(realm, entityID, SAML2Constants.AUTO_FED_ATTRIBUTE);
        if (autoFedAttributes == null || autoFedAttributes.isEmpty()) {
            debug.error("AutoFedSPAccountMapper.getAutoFedUser: " +
                    "Auto federation is enabled but the auto federation attributes are not configured.");
            return null;
        }

        if (debug.messageEnabled()) {
            debug.message("AutoFedSPAccountMapper.getAutoFedUser: Auto federation attributes are set to: "
                    + autoFedAttributes);
        }

        // Concert comma separated string into map
        String[] autoFedAttributesList = autoFedAttributes.split("\\s*,\\s*");
        Map<String, Set<String>> autoFedAttributeMap = new HashMap<>();

        DefaultSPAttributeMapper attributeMapper = new DefaultSPAttributeMapper();
        Map<String, String> attributeMap = attributeMapper.getConfigAttributeMap(realm, entityID, SP);
        Map<String, Set<String>> samlAttributesMap = getSAMLAttributesMap(assertion, decryptionKeys);

        for (String autoFedAttribute : autoFedAttributesList) {
            Set<String> autoFedAttributeValues = samlAttributesMap.get(autoFedAttribute);

            if (null != autoFedAttributeValues) {
                // If attribute mapping exist for this attribute
                if (attributeMap.containsKey(autoFedAttribute)) {
                    autoFedAttribute = attributeMap.get(autoFedAttribute);
                }

                autoFedAttributeMap.put(autoFedAttribute, autoFedAttributeValues);
            }
        }


        try {
            if (debug.messageEnabled()) {
                debug.message("AutoFedSPAccountMapper.getAutoFedUser: Search map: " + autoFedAttributeMap);
            }

            return dsProvider.getUserID(realm, autoFedAttributeMap);
        } catch (DataStoreProviderException dse) {
            if (debug.warningEnabled()) {
                debug.warning("AutoFedSPAccountMapper.getAutoFedUser: Datastore provider exception", dse);
            }
        }

        return null;
    }

    /**
     * Create SAML attribute map for all SAML Attribute statements
     *
     * @param assertion
     * @param decryptionKeys
     *
     * @return
     */
    private Map<String, Set<String>> getSAMLAttributesMap(Assertion assertion, Set<PrivateKey> decryptionKeys) {
        Map<String, Set<String>> samlAttributesMap = new HashMap<>();
        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        if (attributeStatements == null || attributeStatements.isEmpty()) {
            if (debug.messageEnabled()) {
                debug.message("AutoFedSPAccountMapper.getAutoFedUser: " +
                        "Assertion does not have any attribute statements.");
            }

            return samlAttributesMap;
        }

        for (AttributeStatement statement : attributeStatements) {

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

                List<String> values = attribute.getAttributeValueString();
                Set<String> valueSet;
                if (values == null || values.isEmpty()) {
                    valueSet = new HashSet<>();
                } else {
                    valueSet = new HashSet<>(values);
                }

                samlAttributesMap.put(attribute.getName(), valueSet);
            }

        }
        return samlAttributesMap;
    }

}
