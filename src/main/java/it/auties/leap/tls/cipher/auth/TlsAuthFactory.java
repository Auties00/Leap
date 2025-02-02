package it.auties.leap.tls.cipher.auth;

public interface TlsAuthFactory {
    static TlsAuthFactory none() {
        return new TlsAuthFactory() {
            @Override
            public TlsAuth newAuth() {
                return null;
            }

            @Override
            public boolean isAnonymous() {
                return false;
            }
        };
    }

    static TlsAuthFactory anonymous() {
        return new TlsAuthFactory() {
            @Override
            public TlsAuth newAuth() {
                return null;
            }

            @Override
            public boolean isAnonymous() {
                return true;
            }
        };
    }

    static TlsAuthFactory dss() {
        return new TlsAuthFactory() {
            @Override
            public TlsAuth newAuth() {
                return null;
            }

            @Override
            public boolean isAnonymous() {
                return false;
            }
        };
    }

    static TlsAuthFactory eccpwd() {
        return new TlsAuthFactory() {
            @Override
            public TlsAuth newAuth() {
                return null;
            }

            @Override
            public boolean isAnonymous() {
                return false;
            }
        };
    }

    static TlsAuthFactory ecdsa() {
        return new TlsAuthFactory() {
            @Override
            public TlsAuth newAuth() {
                return null;
            }

            @Override
            public boolean isAnonymous() {
                return false;
            }
        };
    }

    static TlsAuthFactory gostr341012_256() {
        return new TlsAuthFactory() {
            @Override
            public TlsAuth newAuth() {
                return null;
            }

            @Override
            public boolean isAnonymous() {
                return false;
            }
        };
    }

    static TlsAuthFactory krb5() {
        return new TlsAuthFactory() {
            @Override
            public TlsAuth newAuth() {
                return null;
            }

            @Override
            public boolean isAnonymous() {
                return false;
            }
        };
    }

    static TlsAuthFactory psk() {
        return new TlsAuthFactory() {
            @Override
            public TlsAuth newAuth() {
                return null;
            }

            @Override
            public boolean isAnonymous() {
                return false;
            }
        };
    }

    static TlsAuthFactory rsa() {
        return new TlsAuthFactory() {
            @Override
            public TlsAuth newAuth() {
                return null;
            }

            @Override
            public boolean isAnonymous() {
                return false;
            }
        };
    }

    static TlsAuthFactory sha() {
        return new TlsAuthFactory() {
            @Override
            public TlsAuth newAuth() {
                return null;
            }

            @Override
            public boolean isAnonymous() {
                return false;
            }
        };
    }

    static TlsAuthFactory sha256() {
        return new TlsAuthFactory() {
            @Override
            public TlsAuth newAuth() {
                return null;
            }

            @Override
            public boolean isAnonymous() {
                return false;
            }
        };
    }

    static TlsAuthFactory sha384() {
        return new TlsAuthFactory() {
            @Override
            public TlsAuth newAuth() {
                return null;
            }

            @Override
            public boolean isAnonymous() {
                return false;
            }
        };
    }

    static TlsAuthFactory shaDss() {
        return new TlsAuthFactory() {
            @Override
            public TlsAuth newAuth() {
                return null;
            }

            @Override
            public boolean isAnonymous() {
                return false;
            }
        };
    }

    static TlsAuthFactory shaRsa() {
        return new TlsAuthFactory() {
            @Override
            public TlsAuth newAuth() {
                return null;
            }

            @Override
            public boolean isAnonymous() {
                return false;
            }
        };
    }

    TlsAuth newAuth();
    boolean isAnonymous();
}
