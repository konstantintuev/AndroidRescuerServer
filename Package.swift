// swift-tools-version:3.1

import PackageDescription

let package = Package(
    name: "perfectServer",
    targets: [],
    dependencies: [
        .Package(url:"https://github.com/PerfectlySoft/Perfect-HTTP.git", majorVersion: 2),
        .Package(url:"https://github.com/PerfectlySoft/Perfect-FastCGI.git", majorVersion: 2, minor: 0),
        .Package(url:"https://github.com/PerfectlySoft/Perfect-MySQL.git", majorVersion: 2),
        .Package(url: "https://github.com/PerfectSideRepos/Turnstile-Perfect.git", majorVersion: 2),
        .Package(url: "https://github.com/PerfectlySoft/Perfect-SMTP.git", majorVersion: 1, minor: 0)
    ]
)
