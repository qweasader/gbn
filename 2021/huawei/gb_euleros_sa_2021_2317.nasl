# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2317");
  script_cve_id("CVE-2021-28651", "CVE-2021-28652", "CVE-2021-28662", "CVE-2021-31806", "CVE-2021-31807", "CVE-2021-31808", "CVE-2021-33620");
  script_tag(name:"creation_date", value:"2021-08-09 10:13:22 +0000 (Mon, 09 Aug 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 11:15:00 +0000 (Fri, 16 Jul 2021)");

  script_name("Huawei EulerOS: Security Advisory for squid (EulerOS-SA-2021-2317)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2317");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2317");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'squid' package(s) announced via the EulerOS-SA-2021-2317 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to incorrect parser validation, it allows a Denial of Service attack against the Cache Manager API. This allows a trusted client to trigger memory leaks that. over time, lead to a Denial of Service via an unspecified short query string. This attack is limited to clients with Cache Manager API access privilege.(CVE-2021-28652)

An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to a buffer-management bug, it allows a denial of service. When resolving a request with the urn: scheme, the parser leaks a small amount of memory. However, there is an unspecified attack methodology that can easily trigger a large amount of memory consumption.(CVE-2021-28651)

An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to a memory-management bug, it is vulnerable to a Denial of Service attack (against all clients using the proxy) via HTTP Range request processing.(CVE-2021-31806)

Squid before 4.15 and 5.x before 5.0.6 allows remote servers to cause a denial of service (affecting availability to all clients) via an HTTP response. The issue trigger is a header that can be expected to exist in HTTP traffic without any malicious intent by the server.(CVE-2021-33620)

An issue was discovered in Squid 4.x before 4.15 and 5.x before 5.0.6. If a remote server sends a certain response header over HTTP or HTTPS, there is a denial of service. This header can plausibly occur in benign network traffic.(CVE-2021-28662)

An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to an input-validation bug, it is vulnerable to a Denial of Service attack (against all clients using the proxy). A client sends an HTTP Range request to trigger this.(CVE-2021-31808)

An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. An integer overflow problem allows a remote server to achieve Denial of Service when delivering responses to HTTP Range requests. The issue trigger is a header that can be expected to exist in HTTP traffic without any malicious intent.(CVE-2021-31807)");

  script_tag(name:"affected", value:"'squid' package(s) on Huawei EulerOS V2.0SP8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~4.2~2.h14.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
