import AppKit
import Foundation
import Vision

for path in CommandLine.arguments.dropFirst() {
    guard let image = NSImage(contentsOfFile: path),
          let cgImage = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
        print("\(path)\tIMAGE_ERROR")
        continue
    }

    let request = VNRecognizeTextRequest()
    request.recognitionLevel = .accurate
    request.recognitionLanguages = ["en-US"]
    request.usesLanguageCorrection = false
    request.regionOfInterest = CGRect(x: 0, y: 0.90, width: 0.45, height: 0.10)

    do {
        try VNImageRequestHandler(cgImage: cgImage).perform([request])
        let text = (request.results ?? [])
            .compactMap { $0.topCandidates(1).first?.string }
            .joined(separator: " | ")
        let normalized = text.replacingOccurrences(
            of: #"(?<=[0-9])(?=[AP]M)"#,
            with: " ",
            options: .regularExpression
        )
        let timestampPattern = #"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{1,2}:[0-9]{2}:[0-9]{2} [AP]M"#
        let timestampRange = normalized.range(of: timestampPattern, options: .regularExpression)
        let epochPattern = #"-([0-9]{13})-"#
        let epochRange = path.range(of: epochPattern, options: .regularExpression)

        var delta = "NA"
        if let timestampRange, let epochRange {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone.current
            formatter.dateFormat = "yyyy-MM-dd h:mm:ss a"
            let epochText = path[epochRange].dropFirst().dropLast()
            if let burnedDate = formatter.date(from: String(normalized[timestampRange])),
               let requestedMs = Double(epochText) {
                delta = String(format: "%.3f", burnedDate.timeIntervalSince1970 - requestedMs / 1000.0)
            }
        }
        print("\(path)\t\(delta)\t\(text)")
    } catch {
        print("\(path)\tOCR_ERROR: \(error)")
    }
}
