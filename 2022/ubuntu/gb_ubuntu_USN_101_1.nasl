# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.101.1");
  script_cve_id("CVE-2004-0911", "CVE-2005-0469");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-101-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-101-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-101-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netkit-telnet' package(s) announced via the USN-101-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow was discovered in the telnet client's handling of
the LINEMODE suboptions. By sending a specially constructed reply
containing a large number of SLC (Set Local Character) commands, a
remote attacker (i. e. a malicious telnet server) could execute
arbitrary commands with the privileges of the user running the telnet
client. (CAN-2005-0469)

Michal Zalewski discovered a Denial of Service vulnerability in the
telnet server (telnetd). A remote attacker could cause the telnetd
process to free an invalid pointer, which caused the server process to
crash, leading to a denial of service (inetd will disable the service
if telnetd crashed repeatedly), or possibly the execution of arbitrary
code with the privileges of the telnetd process (by default,
the 'telnetd' user). Please note that the telnet server is not
officially supported by Ubuntu, it is in the 'universe'
component. (CAN-2004-0911)");

  script_tag(name:"affected", value:"'netkit-telnet' package(s) on Ubuntu 4.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU4.10") {

  if(!isnull(res = isdpkgvuln(pkg:"telnet", ver:"0.17-24ubuntu0.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"telnetd", ver:"0.17-24ubuntu0.1", rls:"UBUNTU4.10"))) {
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
