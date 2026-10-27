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

/// Formats an RDAP domain object (RFC 7483) into a WHOIS-style
/// human-readable representation, e.g. "Domain Name: example.com".
internal enum RDAPFormatter {

    /// Format an RDAP domain object as a WHOIS-style string.
    /// - Parameter object: The parsed JSON object of an RDAP domain response.
    /// - Returns: A multi-line "Field: value" string terminated with a newline.
    static func format(domainObject object: [String: Any]) -> String {
        var lines: [String] = []

        if let ldhName = object["ldhName"] as? String {
            lines.append("Domain Name: \(ldhName)")
        }
        if let handle = object["handle"] as? String {
            lines.append("Registry Domain ID: \(handle)")
        }

        if let events = object["events"] as? [[String: Any]] {
            for event in events {
                guard let action = event["eventAction"] as? String,
                      let date = event["eventDate"] as? String else {
                    continue
                }
                switch action.lowercased() {
                case "registration":
                    lines.append("Creation Date: \(date)")
                case "expiration":
                    lines.append("Registry Expiry Date: \(date)")
                case "last changed":
                    lines.append("Updated Date: \(date)")
                default:
                    break
                }
            }
        }

        if let status = object["status"] as? [String] {
            for item in status {
                lines.append("Domain Status: \(item)")
            }
        }

        if let entities = object["entities"] as? [[String: Any]] {
            for entity in entities {
                RDAPFormatter.format(entity: entity, lines: &lines)
            }
        }

        if let nameservers = object["nameservers"] as? [[String: Any]] {
            for nameserver in nameservers {
                if let ldhName = nameserver["ldhName"] as? String {
                    lines.append("Name Server: \(ldhName)")
                }
            }
        }

        if let secureDNS = object["secureDNS"] as? [String: Any] {
            if let signed = secureDNS["delegationSigned"] as? Bool {
                lines.append("DNSSEC: \(signed ? "signed" : "unsigned")")
            }
            if let dsData = secureDNS["dsData"] as? [[String: Any]] {
                for ds in dsData {
                    var dsLine = "DS Record:"
                    if let keyTag = ds["keyTag"] {
                        dsLine += " keyTag=\(keyTag)"
                    }
                    if let algorithm = ds["algorithm"] {
                        dsLine += " algorithm=\(algorithm)"
                    }
                    if let digestType = ds["digestType"] {
                        dsLine += " digestType=\(digestType)"
                    }
                    if let digest = ds["digest"] {
                        dsLine += " digest=\(digest)"
                    }
                    lines.append(dsLine)
                }
            }
        }

        return lines.joined(separator: "\n") + "\n"
    }

    private static func format(entity: [String: Any], lines: inout [String], labelOverride: String? = nil) {
        let roles = entity["roles"] as? [String] ?? []
        let role = roles.first ?? "entity"
        let label = labelOverride ?? RDAPFormatter.label(for: role)

        if labelOverride == nil {
            if role == "registrar" {
                var ianaID: String?
                if let publicIds = entity["publicIds"] as? [[String: Any]] {
                    ianaID = publicIds.first?["identifier"] as? String
                }
                if ianaID == nil, let handle = entity["handle"] as? String {
                    ianaID = handle
                }
                if let ianaID = ianaID {
                    lines.append("Registrar IANA ID: \(ianaID)")
                }

                if let links = entity["links"] as? [[String: Any]], let href = links.first?["href"] as? String {
                    lines.append("Registrar URL: \(href)")
                }
            } else if let handle = entity["handle"] as? String {
                lines.append("\(label) Registry ID: \(handle)")
            }
        }

        if let vcardArray = entity["vcardArray"] as? [Any] {
            for property in RDAPFormatter.vcardProperties(from: vcardArray) {
                guard property.count >= 4, let name = property[0] as? String else {
                    continue
                }
                RDAPFormatter.format(propertyName: name, value: property[3], label: label, role: role, lines: &lines)
            }
        }

        if let nested = entity["entities"] as? [[String: Any]] {
            let abuseLabel = "\(label) Abuse Contact"
            for child in nested {
                let childRoles = child["roles"] as? [String] ?? []
                if childRoles.contains("abuse") {
                    RDAPFormatter.format(entity: child, lines: &lines, labelOverride: abuseLabel)
                }
            }
        }
    }

    /// Extract the vCard property arrays from an RDAP "vcardArray" value.
    ///
    /// Registries emit the vCard in one of two shapes:
    /// - Flat: `["vcard", [["version", {}, "text", "4.0"], ["fn", ...], ...]]`
    /// - Nested (RFC 7483 jCard): `["vcard", [[["version", ...], ["fn", ...]]]]`
    /// This handles both by treating each element that starts with a string
    /// name as a property, and each element that contains further arrays as
    /// a card whose properties are flattened.
    private static func vcardProperties(from vcardArray: [Any]) -> [[Any]] {
        guard vcardArray.count > 1, let second = vcardArray[1] as? [Any] else {
            return []
        }

        var properties: [[Any]] = []
        for element in second {
            guard let element = element as? [Any], !element.isEmpty else {
                continue
            }
            if element[0] is String {
                // A single property: ["name", params, type, value]
                properties.append(element)
            } else {
                // A card containing properties
                for property in element {
                    if let property = property as? [Any] {
                        properties.append(property)
                    }
                }
            }
        }
        return properties
    }

    private static func format(propertyName name: String, value: Any, label: String, role: String, lines: inout [String]) {
        switch name.lowercased() {
        case "fn":
            if let v = value as? String, !v.isEmpty {
                if role == "registrar" {
                    lines.append("Registrar: \(v)")
                } else {
                    lines.append("\(label) Name: \(v)")
                }
            }
        case "org":
            if let v = value as? String, !v.isEmpty {
                lines.append("\(label) Organization: \(v)")
            }
        case "tel":
            if let v = value as? String {
                let phone = v.hasPrefix("tel:") ? String(v.dropFirst(4)) : v
                if !phone.isEmpty {
                    lines.append("\(label) Phone: \(phone)")
                }
            }
        case "email":
            if let v = value as? String, !v.isEmpty {
                lines.append("\(label) Email: \(v)")
            }
        case "adr":
            if let v = value as? [Any] {
                let parts = v.map { $0 as? String ?? "" }
                // RFC 6350 address components:
                // [pobox, extended, street, locality, region, postal-code, country]
                let street = parts.count > 2 ? parts[2] : ""
                let locality = parts.count > 3 ? parts[3] : ""
                let region = parts.count > 4 ? parts[4] : ""
                let postal = parts.count > 5 ? parts[5] : ""
                let country = parts.count > 6 ? parts[6] : ""

                if !street.isEmpty {
                    lines.append("\(label) Street: \(street)")
                }
                if !locality.isEmpty {
                    lines.append("\(label) City: \(locality)")
                }
                if !region.isEmpty {
                    lines.append("\(label) State/Province: \(region)")
                }
                if !postal.isEmpty {
                    lines.append("\(label) Postal Code: \(postal)")
                }
                if !country.isEmpty {
                    lines.append("\(label) Country: \(country)")
                }
            }
        default:
            break
        }
    }

    private static func label(for role: String) -> String {
        switch role.lowercased() {
        case "registrant":
            return "Registrant"
        case "registrar":
            return "Registrar"
        case "administrative":
            return "Admin"
        case "technical":
            return "Tech"
        case "billing":
            return "Billing"
        case "abuse":
            return "Abuse"
        case "reseller":
            return "Reseller"
        case "sponsor":
            return "Sponsor"
        default:
            return role.capitalized
        }
    }
}
