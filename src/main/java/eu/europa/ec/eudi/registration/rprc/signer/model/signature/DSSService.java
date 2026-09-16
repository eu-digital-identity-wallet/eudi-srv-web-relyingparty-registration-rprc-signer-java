/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.registration.rprc.signer.model.signature;

import eu.europa.ec.eudi.registration.rprc.signer.config.TimestampAuthorityConfig;
import eu.europa.ec.eudi.registration.rprc.signer.exception.RegistrationSignerException.DocumentSignDocParameterInvalidException;
import eu.europa.ec.eudi.registration.rprc.signer.exception.RegistrationSignerException.UnsupportedSignatureFormatException;
import eu.europa.ec.eudi.registration.rprc.signer.web.dto.qtsp.signDoc.DocumentsSignDocRequest;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.cbades.signature.CBAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.validation.OCSPFirstRevocationDataLoadingStrategyFactory;
import eu.europa.esig.dss.spi.validation.RevocationDataVerifier;

import java.security.cert.X509Certificate;
import java.util.*;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;

@Service
public class DSSService {
    private final static Logger logger = LoggerFactory.getLogger(DSSService.class);
	private final TimestampAuthorityConfig timestampAuthorityConfig;

	public DSSService(@Autowired TimestampAuthorityConfig timestampAuthorityConfig){
		this.timestampAuthorityConfig = timestampAuthorityConfig;
	}

    private DSSDocument loadDssDocument(String document, String filename){
        byte[] dataDocument = Base64.getDecoder().decode(document);
		return new InMemoryDocument(dataDocument, filename);
    }

	private DSSDocument loadDssDocument(String document){
		byte[] dataDocument = Base64.getDecoder().decode(document);
		return new InMemoryDocument(dataDocument);
	}

	/*
     * Function that returns the digest of the data to be signed from the document and parameters received
     */
	@SuppressWarnings({ "rawtypes", "unchecked" })
    public byte[] getDigestOfDataToBeSigned(DocumentsSignDocRequest document, X509Certificate certificate,
											CommonTrustedCertificateSource certificateSource, List<X509Certificate> certificateChain,
											String hashAlgorithmOID,  Date date) throws DocumentSignDocParameterInvalidException, UnsupportedSignatureFormatException {

		SignatureDocumentForm form = getSignatureDocumentForm(document, hashAlgorithmOID, certificate, date, certificateSource, certificateChain);
		logger.info("Successfully created the DocumentSignatureForm.");

		DocumentSignatureService service = getSignatureService(form.getContainerType(), form.getSignatureForm(), form.getTrustedCertificates());
		logger.info("Successfully created the DocumentSignatureService");

        AbstractSignatureParameters parameters = fillParameters(form);
		logger.info("Successfully set up SignatureParameters");

        ToBeSigned toBeSigned;
		toBeSigned = service.getDataToSign(form.getDocumentToSign(), parameters);
		logger.info("Successfully retrieved dataToSign.");
		return DSSUtils.digest(parameters.getDigestAlgorithm(), toBeSigned.getBytes());
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public DSSDocument signDocument(DocumentsSignDocRequest document, String hashAlgorithmOID, X509Certificate certificate, Date date,
									CommonTrustedCertificateSource certificateSource, List<X509Certificate> certificateChain, String signature) throws UnsupportedSignatureFormatException, DocumentSignDocParameterInvalidException {
		SignatureDocumentForm form = getSignatureDocumentForm(document, hashAlgorithmOID, certificate, date, certificateSource, certificateChain);
		form.setSignatureValue(Base64.getDecoder().decode(signature));
		logger.info("Successfully created the DocumentSignatureForm.");

		DocumentSignatureService service = getSignatureService(form.getContainerType(), form.getSignatureForm(), form.getTrustedCertificates());
		logger.info("Successfully created the DocumentSignatureService");

		AbstractSignatureParameters parameters = fillParameters(form);
		logger.info("Successfully set up SignatureParameters");

        SignatureValue signatureValue = new SignatureValue();
        signatureValue.setAlgorithm(SignatureAlgorithm.getAlgorithm(form.getEncryptionAlgorithm(), form.getDigestAlgorithm()));
        signatureValue.setValue(form.getSignatureValue());
		logger.info("Successfully created the SignatureValue");

		DSSDocument signedDocument = service.signDocument(form.getDocumentToSign(), parameters, signatureValue);
		logger.info("Successfully retrieved signed document.");
		return signedDocument;
    }

	private SignatureDocumentForm getSignatureDocumentForm(DocumentsSignDocRequest document, String hashAlgorithmOID, X509Certificate certificate, Date date,
														  CommonTrustedCertificateSource certificateSource, List<X509Certificate> certificateChain) throws DocumentSignDocParameterInvalidException {

		SignatureDocumentForm signatureDocumentForm = new SignatureDocumentForm();

		DSSDocument dssDocument;
		if(document.getDocument_name() == null)
			dssDocument = loadDssDocument(document.getDocument());
		else
			dssDocument = loadDssDocument(document.getDocument(), document.getDocument_name());
		logger.debug("Loaded Base64-encoded document to sign as DSSDocument");
		signatureDocumentForm.setDocumentToSign(dssDocument);

		SignaturePackaging signaturePackaging = getSignaturePackaging(document.getSigned_envelope_property());
		signatureDocumentForm.setSignaturePackaging(signaturePackaging);
		ASiCContainerType asicContainerType = getASiCContainerType(document.getContainer());
		signatureDocumentForm.setContainerType(asicContainerType);
		SignatureLevel signatureLevel = getSignatureLevel(document.getConformance_level(), document.getSignature_format());
		signatureDocumentForm.setSignatureLevel(signatureLevel);
		SignatureForm signatureFormat = getSignatureForm(document.getSignature_format());
		signatureDocumentForm.setSignatureForm(signatureFormat);

		DigestAlgorithm digestAlgorithm = getDigestAlgorithmFromOID(hashAlgorithmOID);
		signatureDocumentForm.setDigestAlgorithm(digestAlgorithm);

		signatureDocumentForm.setCertificate(certificate);
		signatureDocumentForm.setCertChain(certificateChain);
		EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forName(certificate.getPublicKey().getAlgorithm());
		signatureDocumentForm.setEncryptionAlgorithm(encryptionAlgorithm);
		signatureDocumentForm.setTrustedCertificates(certificateSource);
		signatureDocumentForm.setDate(date);

		return signatureDocumentForm;
	}

	private static SignatureLevel getSignatureLevel(String conformance_level, String signature_format) throws DocumentSignDocParameterInvalidException {
		String enumValue = getSignatureLevelFromSignatureFormatAndConformanceLevel(conformance_level, signature_format);
		return SignatureLevel.valueByName(enumValue);
	}

	private static String getSignatureLevelFromSignatureFormatAndConformanceLevel(String conformance_level, String signature_format) throws DocumentSignDocParameterInvalidException {
		String prefix = switch (signature_format) {
			case "J" -> "JAdES_BASELINE_";
			case "CB" -> "CB_AdES_BASELINE_";
			default -> {
				logger.error("Signature Format in request is invalid.");
				throw new DocumentSignDocParameterInvalidException("The signature format received is invalid.", "signature_format");
			}
		};

		return switch (conformance_level) {
			case "Ades-B-B" -> prefix + "B";
			case "Ades-B-LT" -> prefix + "LT";
			case "Ades-B-LTA" -> prefix + "LTA";
			case "Ades-B-T" -> prefix + "T";
			default -> {
				logger.error("Conformance Level in request is invalid.");
				throw new DocumentSignDocParameterInvalidException("The conformance level received is invalid.", "conformance_level");
			}
		};
	}

	private static SignatureForm getSignatureForm(String signature_format) throws DocumentSignDocParameterInvalidException {
		return switch (signature_format) {
			case "J" -> SignatureForm.JAdES;
			case "CB" -> SignatureForm.CBAdES;
			default -> {
				logger.error("signature_format is an invalid value.");
				throw new DocumentSignDocParameterInvalidException("The signature_format received is invalid", "signature_format");
			}
		};
	}

	static DigestAlgorithm getDigestAlgorithmFromOID(String algorithmOID) throws DocumentSignDocParameterInvalidException{
		try {
			return DigestAlgorithm.forOID(algorithmOID);
		}
		catch (IllegalArgumentException e){
			logger.info("HashAlgorithmOID given doesn't match a DigestAlgorithm. Try to load SignatureAlgorithm.");

			try {
				SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forOID(algorithmOID);
				return signatureAlgorithm.getDigestAlgorithm();
			}
			catch (IllegalArgumentException e1){
				logger.error("Session_id:{},Signature Digest Algorithm invalid.", RequestContextHolder.currentRequestAttributes().getSessionId());
				throw new DocumentSignDocParameterInvalidException("A valid DigestAlgorithm was not found from the hashAlgorithmOID.", "hashAlgorithmOID");
			}
		}
	}

	private static ASiCContainerType getASiCContainerType(String container) throws DocumentSignDocParameterInvalidException {
		return switch (container) {
			case "No" -> null;
			case "ASiC-E" -> ASiCContainerType.ASiC_E;
			case "ASiC-S" -> ASiCContainerType.ASiC_S;
			default -> {
				logger.error("ASiC Container Type received is invalid.");
				throw new DocumentSignDocParameterInvalidException("The ASiC Container Type is not supported.", "container");
			}
		};
	}

	private static SignaturePackaging getSignaturePackaging(String signedEnvelopeProperty) throws DocumentSignDocParameterInvalidException {
		return switch (signedEnvelopeProperty) {
			case "ENVELOPED" -> SignaturePackaging.ENVELOPED;
			case "ENVELOPING" -> SignaturePackaging.ENVELOPING;
			case "DETACHED" -> SignaturePackaging.DETACHED;
			case "INTERNALLY_DETACHED" -> SignaturePackaging.INTERNALLY_DETACHED;
			default -> {
				logger.error("The signature packaging received is invalid.");
				throw new DocumentSignDocParameterInvalidException("The signedEnvelopeProperty received doesn't match any of the Signature Packaging supported.", "signed_envelope_property");
			}
		};
	}

	@SuppressWarnings("rawtypes")
	private DocumentSignatureService getSignatureService(ASiCContainerType containerType, SignatureForm signatureForm, CommonTrustedCertificateSource trustedCertificates) throws UnsupportedSignatureFormatException {
		CertificateVerifier cv = getCertificateVerifier(trustedCertificates);

		DocumentSignatureService service;
		if (containerType != null) {
			service = (DocumentSignatureService) getASiCSignatureService(signatureForm, cv);
		} else {
			service = switch (signatureForm) {
				case JAdES -> new JAdESService(cv);
				case CBAdES -> new CBAdESService(cv);
				default -> {
					logger.error(String.format("The signature format %s is not supported", signatureForm));
					throw new UnsupportedSignatureFormatException(String.format("The signature format %s is not supported", signatureForm));
				}
			};
		}
		service.setTspSource(getTspSource());
		return service;
	}

	private static CertificateVerifier getCertificateVerifier(CommonTrustedCertificateSource TrustedCertificates) {
		OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
		onlineCRLSource.setDataLoader(new CommonsDataLoader());

		OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
		onlineOCSPSource.setDataLoader(new OCSPDataLoader());
		onlineOCSPSource.setNonceSource(new SecureRandomNonceSource());

		RevocationDataVerifier revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();

		CertificateVerifier cv = new CommonCertificateVerifier();
		cv.setTrustedCertSources(TrustedCertificates);
		cv.setCheckRevocationForUntrustedChains(false);
		cv.setCrlSource(onlineCRLSource);
		cv.setOcspSource(null);
		cv.setAIASource(null); // Capability to download resources from AIA
		cv.setAlertOnMissingRevocationData(new ExceptionOnStatusAlert());
		cv.setAlertOnUncoveredPOE(new LogOnStatusAlert(Level.WARN));
		cv.setAlertOnRevokedCertificate(new ExceptionOnStatusAlert());
		cv.setAlertOnInvalidTimestamp(new ExceptionOnStatusAlert());
		cv.setAlertOnNoRevocationAfterBestSignatureTime(new LogOnStatusAlert(Level.ERROR));
		cv.setAlertOnExpiredCertificate(new ExceptionOnStatusAlert());
		cv.setRevocationDataLoadingStrategyFactory(new OCSPFirstRevocationDataLoadingStrategyFactory());
		cv.setRevocationDataVerifier(revocationDataVerifier);
		cv.setRevocationFallback(true);
		return cv;
	}

	@SuppressWarnings("rawtypes")
	private MultipleDocumentsSignatureService getASiCSignatureService(SignatureForm signatureForm, CertificateVerifier cv) throws UnsupportedSignatureFormatException {
		return switch (signatureForm) {
			case CAdES -> new ASiCWithCAdESService(cv);
			case XAdES -> new ASiCWithXAdESService(cv);
			default -> {
				logger.error(String.format("Signature form selected for an ASiC container (%s) is not supported", signatureForm));
				throw new UnsupportedSignatureFormatException(
					  String.format("Signature form selected for an ASiC container (%s) is not supported", signatureForm));
			}
		};
	}

	private OnlineTSPSource getTspSource(){
		String tspServer = this.timestampAuthorityConfig.getServerUrl();
		OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspServer);
		onlineTSPSource.setDataLoader(new TimestampDataLoader());
		return onlineTSPSource;
	}

	@SuppressWarnings({ "rawtypes" })
	private AbstractSignatureParameters fillParameters(SignatureDocumentForm form) throws UnsupportedSignatureFormatException {
		AbstractSignatureParameters parameters = getSignatureParameters(form.getContainerType(),  form.getSignatureForm());
		fillParameters(parameters, form);
		return parameters;
	}

	@SuppressWarnings({ "rawtypes" })
	private AbstractSignatureParameters getSignatureParameters(ASiCContainerType containerType, SignatureForm signatureForm) throws UnsupportedSignatureFormatException {
		AbstractSignatureParameters parameters;
		if (containerType != null)
			return getASiCSignatureParameters(containerType, signatureForm);

		switch (signatureForm) {
			case JAdES:
				JAdESSignatureParameters jadesParameters = new JAdESSignatureParameters();
				// jadesParameters.setIncludeKeyIdentifier(false);
				jadesParameters.setSignatureType("rc-wrp+jwt");
				jadesParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
				jadesParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI_HASH); // to use by default
				parameters = jadesParameters;
				break;
			case CBAdES:
				CBAdESSignatureParameters cbadesParameters = new CBAdESSignatureParameters();
				parameters = cbadesParameters;
				break;
			default:
				logger.error("Unknown signature format : {}", signatureForm);
				throw new UnsupportedSignatureFormatException(String.format("Unknown signature format : %s", signatureForm));
		}

		return parameters;
	}

	@SuppressWarnings({ "rawtypes" })
	private AbstractSignatureParameters getASiCSignatureParameters(ASiCContainerType containerType, SignatureForm signatureForm) throws UnsupportedSignatureFormatException {
		AbstractSignatureParameters parameters;
		switch (signatureForm) {
			case CAdES:
				ASiCWithCAdESSignatureParameters asicCadesParams = new ASiCWithCAdESSignatureParameters();
				asicCadesParams.aSiC().setContainerType(containerType);
				parameters = asicCadesParams;
				break;
			case XAdES:
				ASiCWithXAdESSignatureParameters asicXadesParams = new ASiCWithXAdESSignatureParameters();
				asicXadesParams.aSiC().setContainerType(containerType);
				parameters = asicXadesParams;
				break;
			default:
				logger.error(String.format("Signature format selected for an ASiC container (%s) is not supported", signatureForm));
				throw new UnsupportedSignatureFormatException(
					  String.format("Signature format selected for an ASiC container (%s) is not supported", signatureForm));
		}
		return parameters;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private void fillParameters(AbstractSignatureParameters parameters, SignatureDocumentForm form) throws UnsupportedSignatureFormatException {
		parameters.setSignaturePackaging(form.getSignaturePackaging());
		parameters.setSignatureLevel(form.getSignatureLevel());
		parameters.setDigestAlgorithm(form.getDigestAlgorithm());
		parameters.setEncryptionAlgorithm(form.getEncryptionAlgorithm());
		parameters.bLevel().setSigningDate(form.getDate());

		CertificateToken signingCertificate = new CertificateToken(form.getCertificate());
		parameters.setSigningCertificate(signingCertificate);

		List<X509Certificate> certificateChainBytes = form.getCertChain();
		List<CertificateToken> certChainToken = new LinkedList<>();
		for (X509Certificate cert : certificateChainBytes) {
			certChainToken.add(new CertificateToken(cert));
		}
		parameters.setCertificateChain(certChainToken);

		fillTimestampParameters(parameters, form);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private void fillTimestampParameters(AbstractSignatureParameters parameters, SignatureDocumentForm form) throws UnsupportedSignatureFormatException {
		SignatureForm signatureForm = form.getSignatureForm();
		ASiCContainerType containerType = form.getContainerType();

		TimestampParameters timestampParameters = getTimestampParameters(containerType, signatureForm);
		timestampParameters.setDigestAlgorithm(form.getDigestAlgorithm());

		parameters.setContentTimestampParameters(timestampParameters);
		parameters.setSignatureTimestampParameters(timestampParameters);
		parameters.setArchiveTimestampParameters(timestampParameters);
	}

	private TimestampParameters getTimestampParameters(ASiCContainerType containerType, SignatureForm signatureForm) throws UnsupportedSignatureFormatException {
		TimestampParameters parameters;
		if (containerType == null) {
			parameters = switch (signatureForm) {
				case JAdES -> new JAdESTimestampParameters();
				case CBAdES -> new CBAdESTimestampParameters();
				default -> {
					logger.error(String.format("Signature format selected for a time-stamp (%s) is not supported.", signatureForm));
					throw new UnsupportedSignatureFormatException(
						  String.format("Signature format selected for a time-stamp (%s) is not supported.", signatureForm));
				}
			};

		} else {
			switch (signatureForm) {
				case CAdES:
					ASiCWithCAdESTimestampParameters asicParameters = new ASiCWithCAdESTimestampParameters();
					asicParameters.aSiC().setContainerType(containerType);
					parameters = asicParameters;
					break;
				case XAdES:
					parameters = new XAdESTimestampParameters();
					break;
				default:
					logger.error(String.format("Signature format selected for an ASiC time-stamp (%s) is not supported.", signatureForm));
					throw new UnsupportedSignatureFormatException(
						  String.format("Signature format selected for an ASiC time-stamp (%s) is not supported.", signatureForm));
			}
		}
		return parameters;
	}
}