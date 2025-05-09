package it.auties.leap.tls.rfc;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * An annotation that specifies a requirement mandated by an RFC
 */
@Retention(RetentionPolicy.SOURCE)
public @interface TlsSpecificationRequirement {
    /**
     * The level of requirement specified
     */
    TlsSpecRequirementLevel level();

    /**
     * A link to the document, alongside the section if needed, that mandates the requirement
     */
    String source();
}
