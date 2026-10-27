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
    }

    func testWHOISFallbackToRDAP() async throws {
        // The .web TLD has no WHOIS server, so the WHOIS lookup should fall
        // back to an RDAP lookup and return the RDAP reply as a WHOISReply.
        let (server, _) = WHOISClient.getLookupHost(for: "nic.web")
        XCTAssertNil(server)

        let result = try await WHOISClient.lookup("nic.web")
        XCTAssertTrue(result.count > 0)
    }

    func testWHOISFallbackToRDAPWhenWHOISFails() async throws {
        // The .app TLD has a WHOIS server entry (whois.nic.app) but Google
        // Registry does not actually run a port 43 WHOIS service, so the
        // WHOIS query fails and the lookup must fall back to RDAP.
        let (server, _) = WHOISClient.getLookupHost(for: "foxterm.app")
        XCTAssertEqual(server, "whois.nic.app")

        let result = try await WHOISClient.lookup("foxterm.app")
        XCTAssertTrue(result.count > 0)
    }
}
