package it.auties.leap.tls.rfc;

/**
 * <a href="https://datatracker.ietf.org/doc/html/rfc2119">RFC2119 - Abstract</a>
 * <p>
 *  In many standards track documents several words are used to signify
 *  the requirements in the specification.  These words are often
 *  capitalized.  This document defines these words as they should be
 *  interpreted in IETF documents.  Authors who follow these guidelines
 *  should incorporate this phrase near the beginning of their document:
 */
public enum TlsSpecRequirementLevel {
    /**
     * 1. MUST   This word, or the terms "REQUIRED" or "SHALL", mean that the
     *    definition is an absolute requirement of the specification.
     */
    MUST,

    /**
     * 2. MUST NOT   This phrase, or the phrase "SHALL NOT", mean that the
     *    definition is an absolute prohibition of the specification.
     */
    MUST_NOT,

    /**
     * 3. SHOULD   This word, or the adjective "RECOMMENDED", mean that there
     *    may exist valid reasons in particular circumstances to ignore a
     *    particular item, but the full implications must be understood and
     *    carefully weighed before choosing a different course.
     */
    SHOULD,

    /**
     * 4. SHOULD NOT   This phrase, or the phrase "NOT RECOMMENDED" mean that
     *    there may exist valid reasons in particular circumstances when the
     *    particular behavior is acceptable or even useful, but the full
     *    implications should be understood and the case carefully weighed
     *    before implementing any behavior described with this label.
     */
    SHOULD_NOT,

    /**
     * 5. MAY   This word, or the adjective "OPTIONAL", mean that an item is
     *    truly optional.  One vendor may choose to include the item because a
     *    particular marketplace requires it or because the vendor feels that
     *    it enhances the product while another vendor may omit the same item.
     *    An implementation which does not include a particular option MUST be
     *    prepared to interoperate with another implementation which does
     *    include the option, though perhaps with reduced functionality. In the
     *    same vein an implementation which does include a particular option
     *    MUST be prepared to interoperate with another implementation which
     *    does not include the option (except, of course, for the feature the
     *    option provides.)
     */
    MAY
}
