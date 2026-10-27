// DNSKit
// Copyright (C) Ian Spence and other DNSKit Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import XCTest
@testable import DNSKit

final class RDAPTests: XCTestCase {
    func getLookupHostForDomain(_ input: String, expectedServer: String, expectedBare: String) {
        let (actualServer, actualBare) = RDAPClient.getLookupHost(for: input)

        XCTAssertNotNil(actualServer)
        XCTAssertNotNil(actualBare)
        XCTAssertEqual(expectedServer, actualServer)
        XCTAssertEqual(expectedBare, actualBare)
    }

    func testGetLookupHostForDomain() {
        getLookupHostForDomain("example.com", expectedServer: "https://rdap.verisign.com/com/v1/", expectedBare: "example.com")
        getLookupHostForDomain("example.example.example.com", expectedServer: "https://rdap.verisign.com/com/v1/", expectedBare: "example.com")
        getLookupHostForDomain("example.app", expectedServer: "https://pubapi.registry.google/rdap/", expectedBare: "example.app")
        getLookupHostForDomain("example.example.example.app", expectedServer: "https://pubapi.registry.google/rdap/", expectedBare: "example.app")
        getLookupHostForDomain("example.co.uk", expectedServer: "https://rdap.nominet.uk/uk/", expectedBare: "co.uk")
        getLookupHostForDomain("example.org", expectedServer: "https://rdap.publicinterestregistry.org/rdap/", expectedBare: "example.org")

        let (bogusServer, bogusBare) = RDAPClient.getLookupHost(for: "example.bogusnotatld")
        XCTAssertNil(bogusServer)
        XCTAssertNil(bogusBare)
    }

    func testRDAPLookup() async throws {
        let result = try await RDAPClient.lookup("example.com")
        XCTAssertTrue(result.count > 0)
        XCTAssertTrue(result[0].data.contains("Domain Name: EXAMPLE.COM"))
    }

    func testRDAPFormatter() throws {
        let json = """
        {
          "ldhName": "example.com",
          "handle": "2336799_DOMAIN_COM-VRSN",
          "status": ["client delete prohibited"],
          "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2026-08-14T08:01:43Z"}
          ],
          "entities": [
            {
              "roles": ["registrar"],
              "handle": "376",
              "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
              "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "ICANN"]
              ]],
              "entities": [
                {
                  "roles": ["abuse"],
                  "vcardArray": ["vcard", [
                    ["version", {}, "text", "4.0"],
                    ["email", {}, "text", "abuse@example.com"],
                    ["tel", {}, "uri", "tel:+1.1234567890"]
                  ]]
                }
              ]
            },
            {
              "roles": ["registrant"],
              "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Jane Doe"],
                ["org", {}, "text", "Example Org"],
                ["adr", {}, "text", ["", "", "1 Example St", "Springfield", "IL", "62701", "US"]],
                ["tel", {}, "uri", "tel:+1.5551234567"],
                ["email", {}, "text", "jane@example.com"]
              ]]
            }
          ],
          "nameservers": [
            {"ldhName": "A.IANA-SERVERS.NET"},
            {"ldhName": "B.IANA-SERVERS.NET"}
          ],
          "secureDNS": {
            "delegationSigned": true,
            "dsData": [{"keyTag": 2371, "algorithm": 13, "digestType": 2, "digest": "169521AB547DF3A14C1719A0F0D5289278E22682B53CE9F22D379B922125BF98"}]
          }
        }
        """
        let data = try XCTUnwrap(json.data(using: .utf8))
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let output = RDAPFormatter.format(domainObject: object)

        for expected in [
            "Domain Name: example.com",
            "Registry Domain ID: 2336799_DOMAIN_COM-VRSN",
            "Creation Date: 1995-08-14T04:00:00Z",
            "Registry Expiry Date: 2027-08-13T04:00:00Z",
            "Updated Date: 2026-08-14T08:01:43Z",
            "Domain Status: client delete prohibited",
            "Registrar: ICANN",
            "Registrar IANA ID: 376",
            "Registrar Abuse Contact Email: abuse@example.com",
            "Registrar Abuse Contact Phone: +1.1234567890",
            "Registrant Name: Jane Doe",
            "Registrant Organization: Example Org",
            "Registrant Street: 1 Example St",
            "Registrant City: Springfield",
            "Registrant State/Province: IL",
            "Registrant Postal Code: 62701",
            "Registrant Country: US",
            "Registrant Phone: +1.5551234567",
            "Registrant Email: jane@example.com",
            "Name Server: A.IANA-SERVERS.NET",
            "Name Server: B.IANA-SERVERS.NET",
            "DNSSEC: signed",
            "DS Record: keyTag=2371 algorithm=13 digestType=2 digest=169521AB547DF3A14C1719A0F0D5289278E22682B53CE9F22D379B922125BF98",
        ] {
            XCTAssertTrue(output.contains(expected), "Missing \(expected) in:\n\(output)")
        }
    }

    func testWHOISFallbackToRDAP() async throws {
        // The .web TLD has no WHOIS server, so the lookup host falls back
        // to the RDAP server and the WHOIS lookup returns the RDAP reply
        // as a WHOISReply.
        let (server, _) = WHOISClient.getLookupHost(for: "nic.web")
        XCTAssertEqual(server, "https://tld-rdap.verisign.com/web/v1/")

        let result = try await WHOISClient.lookup("nic.web")
        XCTAssertTrue(result.count > 0)
    }

    func testWHOISStrictMatchFallsBackToRDAP() async throws {
        // The .app TLD is a Google Registry gTLD that does not run a WHOIS
        // service. It is not strictly matched to a WHOIS server, so the
        // lookup host falls back to the RDAP server and the lookup runs
        // against RDAP without attempting WHOIS.
        let (server, _) = WHOISClient.getLookupHost(for: "foxterm.app")
        XCTAssertEqual(server, "https://pubapi.registry.google/rdap/")

        let result = try await WHOISClient.lookup("foxterm.app")
        XCTAssertTrue(result.count > 0)
    }
}
