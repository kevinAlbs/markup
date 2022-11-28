A utility for testing the [Automatic Encryption Shared Library](https://www.mongodb.com/docs/manual/core/queryable-encryption/reference/shared-library/).

Example:
```
$ export CRYPT_SHARED_PATH=/home/kevin/bin/mongo_crypt_shared_v1-linux-x86_64-enterprise-ubuntu1804-6.0/lib/mongo_crypt_v1.so
$ cat example-input.json | python markup.py
{
    "hasEncryptionPlaceholders": true,
    "schemaRequiresEncryption": true,
    "result": {
        "find": "test",
        "filter": {
            "value": {
                "$eq": {
                    "$binary": {
                        "base64": "A1gAAAAQdAACAAAAEGEAAgAAAAVraQAQAAAABBI0VngSNJh2EjQSNFZ4kBIFa3UAEAAAAAQSNFZ4EjSYdhI0EjRWeJASEHYAQOIBABJjbQAAAAAAAAAAAAA=",
                        "subType": "06"
                    }
                }
            }
        },
        "encryptionInformation": {
            "type": {
                "$numberInt": "1"
            },
            "schema": {
                "db.test": {
                    "escCollection": "esc",
                    "eccCollection": "ecc",
                    "ecocCollection": "ecoc",
                    "fields": [
                        {
                            "keyId": {
                                "$binary": {
                                    "base64": "EjRWeBI0mHYSNBI0VniQEg==",
                                    "subType": "04"
                                }
                            },
                            "path": "value",
                            "bsonType": "int",
                            "queries": {
                                "queryType": "equality",
                                "contention": {
                                    "$numberLong": "0"
                                }
                            }
                        }
                    ]
                }
            }
        }
    }
}
```

`markup.py` depends on cffi. Use `pip install cffi`.
