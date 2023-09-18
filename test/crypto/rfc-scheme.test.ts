import {mainnetClient, timelockDecrypt} from "../../src"

describe("rfc compliant scheme", () => {
    it("should pass test vectors from go codebase", async () => {
        const ciphertext = "-----BEGIN AGE ENCRYPTED FILE-----\n" +
            "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDc0NjUxMSA1MmRiOWJhNzBl\n" +
            "MGNjMGY2ZWFmNzgwM2RkMDc0NDdhMWY1NDc3NzM1ZmQzZjY2MTc5MmJhOTQ2MDBj\n" +
            "ODRlOTcxCmtEWkJHdnVveWVDeGI5MVBYVWgvY2pOWUdrcElRQU95dFhvUk9WbUNh\n" +
            "dkVaeUN3OUVMR1ZBWE4zcTZKMlBrYmkKQURyQWVNdWJuMyswODJOVDNSR1ZCMDBv\n" +
            "Nzg2MHhVMnl3N0pCbVV4eFY0UGJHZTREaWh2NWJrKzVibzVHRkRJUwpGaGFoS21R\n" +
            "UVFrSDJyOEF6VkNHRXc5ekxPaGRQMktlbmxUSFhEREplc3JnCi0tLSBpMndTSkZI\n" +
            "MnFveWFqSnhTOXhEazJSN2E2dWRKNWZReDBiUlRnZnFYak1zCnw2ccNps+whQe+p\n" +
            "qVlJAYqlmEB4qFMRif9Z518uFEfAX5e5AyeQtVJcdfU3\n" +
            "-----END AGE ENCRYPTED FILE-----\n"

        const expectedPlaintext = "hello world\n"
        const actualPlaintext = await timelockDecrypt(ciphertext, mainnetClient())

        expect(actualPlaintext.toString()).toEqual(expectedPlaintext.toString())
    })
})