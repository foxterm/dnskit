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

import Foundation

/// Describes a reply to an RDAP query
public struct RDAPReply: Sendable {
    /// The server which produced this reply. This will either be a domain name or IP address.
    public let server: String
    /// The reply data
    public let data: String
}

/// RDAP related utilities
public struct RDAPClient: Sendable {
    private static let userAgent = "DNSKit (github.com/dns-inspector/dnskit)"
    private static let lookupTimeoutSeconds: TimeInterval = 15

    /// Perform an RDAP lookup on the given domain name
    /// - Parameter domain: The domain name to query
    /// - Returns: Returns the RDAP response data
    /// - Throws: Will throw if unable to perform the lookup
    ///
    /// > Tip: RDAP data is always returned as a pretty-printed JSON string.
    @available(iOS 13.0, macOS 10.15, *)
    public static func lookup(_ domain: String) async throws -> [RDAPReply] {
        return try await withCheckedThrowingContinuation { continuation in
            self.lookup(domain) { result in
                continuation.resume(with: result)
            }
        }
    }

    /// Perform an RDAP lookup on the given domain name
    /// - Parameters:
    ///   - domain: The domain name to query
    ///   - complete: Callback called when the lookup has completed with a result or an error.
    ///
    /// > Tip: RDAP data is always returned as a pretty-printed JSON string.
    public static func lookup(_ domain: String, complete: @Sendable @escaping (Result<[RDAPReply], RDAPError>) -> Void) {
        let (oBaseURL, oBareDomain) = RDAPClient.getLookupHost(for: domain)
        guard let baseURL = oBaseURL else {
            printError("[\(#fileID):\(#line)] Unsuported TLD for RDAP lookup: \(domain)")
            complete(.failure(.rdapNotSupported))
            return
        }
        guard let bareDomain = oBareDomain else {
            printError("[\(#fileID):\(#line)] Unsuported TLD for RDAP lookup: \(domain)")
            complete(.failure(.rdapNotSupported))
            return
        }

        var urlString = baseURL
        if !urlString.hasSuffix("/") {
            urlString += "/"
        }
        urlString += "domain/"
        guard let encodedDomain = bareDomain.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) else {
            printError("[\(#fileID):\(#line)] Unable to encode domain for RDAP lookup: \(bareDomain)")
            complete(.failure(.invalidResponse("Unable to encode domain")))
            return
        }
        urlString += encodedDomain
        let requestURLString = urlString
        guard let url = URL(string: requestURLString) else {
            printError("[\(#fileID):\(#line)] Invalid RDAP URL: \(requestURLString)")
            complete(.failure(.invalidResponse("Invalid URL: \(requestURLString)")))
            return
        }

        printDebug("[\(#fileID):\(#line)] Performing RDAP lookup for \(bareDomain) on \(url)")

        var request = URLRequest(url: url)
        request.setValue("application/rdap+json, application/json", forHTTPHeaderField: "Accept")
        request.setValue(RDAPClient.userAgent, forHTTPHeaderField: "User-Agent")

        let sessionConfig = URLSessionConfiguration.default
        sessionConfig.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        sessionConfig.timeoutIntervalForResource = RDAPClient.lookupTimeoutSeconds
        sessionConfig.httpCookieStorage = nil
        sessionConfig.httpShouldSetCookies = false
        let session = URLSession(configuration: sessionConfig)

        let task = session.dataTask(with: request) { oData, oResponse, oError in
            if let error = oError as? NSError {
                if error.code == NSURLErrorTimedOut {
                    printError("[\(#fileID):\(#line)] Error sending RDAP query to \(url): timed out")
                    complete(.failure(.timedOut))
                    return
                }
                printError("[\(#fileID):\(#line)] Error sending RDAP query to \(url): \(error)")
                complete(.failure(.connectionError(error)))
                return
            }

            guard let response = oResponse as? HTTPURLResponse else {
                printError("[\(#fileID):\(#line)] Error sending RDAP query to \(url): no response")
                complete(.failure(.emptyResponse))
                return
            }

            if response.statusCode != 200 {
                printError("[\(#fileID):\(#line)] Error sending RDAP query to \(url): HTTP \(response.statusCode)")
                complete(.failure(.invalidResponse("HTTP \(response.statusCode)")))
                return
            }

            guard let data = oData, data.count > 0 else {
                printWarning("[\(#fileID):\(#line)] RDAP server provided no data")
                complete(.failure(.emptyResponse))
                return
            }

            // Validate the response is JSON and pretty-print it so the reply
            // data is human-readable, matching the WHOIS reply convention.
            do {
                let object = try JSONSerialization.jsonObject(with: data)
                let prettyData = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
                guard let prettyString = String(data: prettyData, encoding: .utf8) else {
                    printError("[\(#fileID):\(#line)] Unable to decode RDAP response from \(url)")
                    complete(.failure(.invalidResponse("Unable to decode RDAP response")))
                    return
                }
                printDebug("[\(#fileID):\(#line)] RDAP response: \(prettyString)")
                complete(.success([RDAPReply(server: requestURLString, data: prettyString)]))
            } catch {
                printError("[\(#fileID):\(#line)] Invalid RDAP response from \(url): \(error)")
                complete(.failure(.invalidResponse(error.localizedDescription)))
            }
        }

        task.resume()
    }

    /// Get the RDAP server base URL for the given domain name.
    /// - Parameter domain: The domain name to query for
    /// - Returns: A tuple of two optional strings. The first is the lookup server base URL, the second is the bare URL for querying (without any subdomains).
    public static func getLookupHost(for domain: String) -> (String?, String?) {
        if domain.count == 0 || domain.count > 250 {
            return (nil, nil)
        }

        var input = domain.lowercased()
        if input.hasSuffix(".") {
            input = String(input.dropLast())
        }

        let parts = input.split(separator: ".")
        guard let last = parts.last else {
            return (nil, nil)
        }
        let tld = String(last)

        let rdapServ = RDAPClient.getRdapServ()
        guard let baseURL = rdapServ[tld] else {
            return (nil, nil)
        }

        let bareDomain = parts.count >= 2 ? "\(parts[parts.count-2]).\(tld)" : input
        return (baseURL, bareDomain)
    }
}
