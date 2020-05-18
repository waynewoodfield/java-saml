package com.onelogin.saml2.settings;

import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.xpath.XPathExpressionException;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;

import com.onelogin.saml2.util.Constants;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.text.StrSubstitutor;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import com.onelogin.saml2.model.Contact;
import com.onelogin.saml2.model.Organization;
import com.onelogin.saml2.util.Util;

/**
 * Metadata class of OneLogin's Java Toolkit.
 *
 * A class that contains methods related to the metadata of the SP
 */
public class IdpMetadata {
  /**
   * Private property to construct a logger for this class.
   */
  private static final Logger LOGGER = LoggerFactory.getLogger(Metadata.class);

  // Constants
  private static final int N_DAYS_VALID_UNTIL = 90;
  private static final int SECONDS_CACHED = 604800; // 1 week

  /**
   * Generated metadata in string format
   */
  private final String metadataString;

  /**
   * validUntilTime of the metadata. How long the metadata is valid
   */
  private final Calendar validUntilTime;

  /**
   * cacheDuration of the metadata. Duration of the cache in seconds
   */
  private final Integer cacheDuration;

  /**
   * Constructs the Metadata object.
   *
   * @param settings
   * 				Saml2Settings object. Setting data
   * @param validUntilTime
   * 				Metadata's valid time
   * @param cacheDuration
   * 				Duration of the cache in seconds
   * @throws CertificateEncodingException
   */
  public IdpMetadata(Saml2Settings settings, Calendar validUntilTime, Integer cacheDuration) throws CertificateEncodingException {
    if (validUntilTime == null) {
      this.validUntilTime = Calendar.getInstance();
      this.validUntilTime.add(Calendar.DAY_OF_YEAR, N_DAYS_VALID_UNTIL);
    } else {
      this.validUntilTime = validUntilTime;
    }

    if (cacheDuration == null) {
      this.cacheDuration = SECONDS_CACHED;
    } else {
      this.cacheDuration = cacheDuration;
    }

    StrSubstitutor substitutor = generateSubstitutor(settings);
    String unsignedMetadataString = substitutor.replace(getMetadataTemplate());

    LOGGER.debug("metadata --> " + unsignedMetadataString);
    metadataString = unsignedMetadataString;
  }

  /**
   * Constructs the Metadata object.
   *
   * @param settings
   * 				Saml2Settings object. Setting data
   *
   * @throws CertificateEncodingException
   */
  public IdpMetadata(Saml2Settings settings) throws CertificateEncodingException {
    this(settings, null, null);
  }

  /**
   * Substitutes metadata variables within a string by values.
   *
   * @param settings
   * 				Saml2Settings object. Setting data
   *
   * @return the StrSubstitutor object of the metadata
   */
  private StrSubstitutor generateSubstitutor(Saml2Settings settings) throws CertificateEncodingException {

    Map<String, String> valueMap = new HashMap<String, String>();

    valueMap.put("id", Util.generateUniqueID());
    valueMap.put("validUntilTime", Util.formatDateTime(validUntilTime.getTimeInMillis()));
    valueMap.put("cacheDuration", String.valueOf(cacheDuration));
    valueMap.put("idpEntityId", settings.getIdpEntityId());
    valueMap.put("strAuthnsign", String.valueOf(settings.getAuthnRequestsSigned()));
    valueMap.put("strWsign", String.valueOf(settings.getWantAssertionsSigned()));
    valueMap.put("spNameIDFormat", settings.getSpNameIDFormat());
    valueMap.put("redirectBinding", Constants.BINDING_HTTP_REDIRECT);
    valueMap.put("postBinding", Constants.BINDING_HTTP_POST);
    valueMap.put("idpSingleSignOnServiceUrl", settings.getIdpSingleSignOnServiceUrl().toString());
    valueMap.put("idpSingleLogoutServiceUrl", settings.getIdpSingleLogoutServiceUrl().toString());

    valueMap.put("strKeyDescriptor", toX509KeyDescriptorsXML(settings));
    valueMap.put("strContacts", toContactsXml(settings.getContacts()));
    valueMap.put("strOrganization", toOrganizationXml(settings.getOrganization()));

    return new StrSubstitutor(valueMap);
  }

  /**
   * @return the metadata's template
   */
  private static StringBuilder getMetadataTemplate() {

    StringBuilder template = new StringBuilder();
    template.append("<?xml version=\"1.0\"?>");
    template.append("<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"");
    template.append(" validUntil=\"${validUntilTime}\" cacheDuration=\"PT${cacheDuration}S\" entityID=\"${idpEntityId}\" ID=\"${id}\">");
    template.append("<md:IDPSSODescriptor WantAuthnRequestsSigned=\"${strAuthnsign}\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">");
    template.append("${strKeyDescriptor}");
    template.append("<md:NameIDFormat>${spNameIDFormat}</md:NameIDFormat>");
    template.append("<md:SingleSignOnService Binding=\"${redirectBinding}\" Location=\"${idpSingleSignOnServiceUrl}\"/>");
    template.append("<md:SingleSignOnService Binding=\"${postBinding}\" Location=\"${idpSingleSignOnServiceUrl}\"/>");
    template.append("<md:SingleLogoutService Binding=\"${redirectBinding}\" Location=\"${idpSingleLogoutServiceUrl}\"/>");
    template.append("<md:SingleLogoutService Binding=\"${postBinding}\" Location=\"${idpSingleLogoutServiceUrl}\"/>");
    template.append("</md:IDPSSODescriptor>${strOrganization}${strContacts}");
    template.append("</md:EntityDescriptor>");

    return template;
  }

  /**
   * Generates the contact section of the metadata's template
   *
   * @param contacts
   * 				List of contact objects
   *
   * @return the contact section of the metadata's template
   */
  private String toContactsXml(List<Contact> contacts) {
    StringBuilder contactsXml = new StringBuilder();

    for (Contact contact : contacts) {
      contactsXml.append("<md:ContactPerson contactType=\"" + contact.getContactType() + "\">");
      contactsXml.append("<md:GivenName>" + contact.getGivenName() + "</md:GivenName>");
      contactsXml.append("<md:EmailAddress>" + contact.getEmailAddress() + "</md:EmailAddress>");
      contactsXml.append("</md:ContactPerson>");
    }

    return contactsXml.toString();
  }

  /**
   * Generates the organization section of the metadata's template
   *
   * @param organization
   * 				organization object
   *  @return the organization section of the metadata's template
   */
  private String toOrganizationXml(Organization organization) {
    String orgXml = "";

    if (organization != null) {
      String lang = organization.getOrgLangAttribute();
      orgXml = "<md:Organization><md:OrganizationName xml:lang=\"" + lang + "\">" + organization.getOrgName()
              + "</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"" + lang + "\">"
              + organization.getOrgDisplayName() + "</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\""
              + lang + "\">" + organization.getOrgUrl() + "</md:OrganizationURL></md:Organization>";
    }
    return orgXml;
  }

  /**
   * Generates the KeyDescriptor section of the metadata's template
   *
   * @param settings
   * 				the Saml2Settings object that contains the public cert that will be used by the SP to sign and encrypt, and your signing/encryption preferences
   *
   * @return the KeyDescriptor section of the metadata's template
   */
  private String toX509KeyDescriptorsXML(Saml2Settings settings) throws CertificateEncodingException {
    StringBuilder keyDescriptorXml = new StringBuilder();

    X509Certificate cert = settings.getIdpx509cert();
    if (cert != null) {
      Base64 encoder = new Base64(64);
      byte[] encodedCert = cert.getEncoded();
      String certString = new String(encoder.encode(encodedCert));

      if (settings.getWantAssertionsSigned() || settings.getLogoutRequestSigned() || settings.getLogoutResponseSigned()) {
        keyDescriptorXml.append("<md:KeyDescriptor use=\"signing\">");
        keyDescriptorXml.append("<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">");
        keyDescriptorXml.append("<ds:X509Data>");
        keyDescriptorXml.append("<ds:X509Certificate>").append(certString).append("</ds:X509Certificate>");
        keyDescriptorXml.append("</ds:X509Data>");
        keyDescriptorXml.append("</ds:KeyInfo>");
        keyDescriptorXml.append("</md:KeyDescriptor>");
      }
      if (settings.getWantAuthnRequestsEncrypted()) {
        keyDescriptorXml.append("<md:KeyDescriptor use=\"encryption\">");
        keyDescriptorXml.append("<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">");
        keyDescriptorXml.append("<ds:X509Data>");
        keyDescriptorXml.append("<ds:X509Certificate>").append(certString).append("</ds:X509Certificate>");
        keyDescriptorXml.append("</ds:X509Data>");
        keyDescriptorXml.append("</ds:KeyInfo>");
        keyDescriptorXml.append("</md:KeyDescriptor>");
      }
    }

    return keyDescriptorXml.toString();
  }

  /**
   * @return the metadata
   */
  public final String getMetadataString() {
    return metadataString;
  }

  /**
   * Signs the metadata with the key/cert provided
   *
   * @param metadata
   * 				SAML Metadata XML
   * @param key
   *       		Private Key
   * @param cert
   *      		x509 Public certificate
   * @param signAlgorithm
   * 				Signature Algorithm
   *
   * @return string Signed Metadata
   * @throws XMLSecurityException
   * @throws XPathExpressionException
   */
  public static String signMetadata(String metadata, PrivateKey key, X509Certificate cert, String signAlgorithm) throws XPathExpressionException, XMLSecurityException
  {
    Document metadataDoc = Util.loadXML(metadata);
    String signedMetadata = Util.addSign(metadataDoc, key, cert, signAlgorithm);
    LOGGER.debug("Signed metadata --> " + signedMetadata);
    return signedMetadata;
  }
}
