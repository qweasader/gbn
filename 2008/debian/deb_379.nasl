# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53374");
  script_cve_id("CVE-2003-0773", "CVE-2003-0774", "CVE-2003-0775", "CVE-2003-0776", "CVE-2003-0777", "CVE-2003-0778");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-379)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-379");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-379");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-379");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sane-backends' package(s) announced via the DSA-379 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexander Hvostov, Julien Blache and Aurelien Jarno discovered several security-related problems in the sane-backends package, which contains an API library for scanners including a scanning daemon (in the package libsane) that can be remotely exploited. These problems allow a remote attacker to cause a segmentation fault and/or consume arbitrary amounts of memory. The attack is successful, even if the attacker's computer isn't listed in saned.conf.

You are only vulnerable if you actually run saned e.g. in xinetd or inetd. If the entries in the configuration file of xinetd or inetd respectively are commented out or do not exist, you are safe.

Try 'telnet localhost 6566' on the server that may run saned. If you get 'connection refused' saned is not running and you are safe.

The Common Vulnerabilities and Exposures project identifies the following problems: CAN-2003-0773: saned checks the identity (IP address) of the remote host only after the first communication took place (SANE_NET_INIT). So everyone can send that RPC, even if the remote host is not allowed to scan (not listed in saned.conf). CAN-2003-0774: saned lacks error checking nearly everywhere in the code. So connection drops are detected very late. If the drop of the connection isn't detected, the access to the internal wire buffer leaves the limits of the allocated memory. So random memory 'after' the wire buffer is read which will be followed by a segmentation fault. CAN-2003-0775: If saned expects strings, it mallocs the memory necessary to store the complete string after it receives the size of the string. If the connection was dropped before transmitting the size, malloc will reserve an arbitrary size of memory. Depending on that size and the amount of memory available either malloc fails (->saned quits nicely) or a huge amount of memory is allocated. Swapping and OOM measures may occur depending on the kernel. CAN-2003-0776: saned doesn't check the validity of the RPC numbers it gets before getting the parameters. CAN-2003-0777: If debug messages are enabled and a connection is dropped, non-null-terminated strings may be printed and segmentation faults may occur. CAN-2003-0778: It's possible to allocate an arbitrary amount of memory on the server running saned even if the connection isn't dropped. At the moment this cannot easily be fixed according to the author. Better limit the total amount of memory saned may use (ulimit). For the stable distribution (woody) this problem has been fixed in version 1.0.7-4. For the unstable distribution (sid) this problem has been fixed in version 1.0.11-1 and later. We recommend that you upgrade your libsane packages.");

  script_tag(name:"affected", value:"'sane-backends' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"libsane", ver:"1.0.7-4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsane-dev", ver:"1.0.7-4", rls:"DEB3.0"))) {
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
