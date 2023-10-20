# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.27");
  script_cve_id("CVE-2014-0207", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DLA-27)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-27");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/dla-27");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'file' package(s) announced via the DLA-27 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fix various denial of service attacks:

CVE-2014-3487

The cdf_read_property_info function does not properly validate a stream offset, which allows remote attackers to cause a denial of service (application crash) via a crafted CDF file.

CVE-2014-3480

The cdf_count_chain function in cdf.c in does not properly validate sector-count data, which allows remote attackers to cause a denial of service (application crash) via a crafted CDF file.

CVE-2014-3479

The cdf_check_stream_offset function in cdf.c relies on incorrect sector-size data, which allows remote attackers to cause a denial of service (application crash) via a crafted stream offset in a CDF file.

CVE-2014-3478

Buffer overflow in the mconvert function in softmagic.c allows remote attackers to cause a denial of service (application crash) via a crafted Pascal string in a FILE_PSTRING conversion.

CVE-2014-0238

The cdf_read_property_info function in cdf.c allows remote attackers to cause a denial of service (infinite loop or out-of-bounds memory access) via a vector that (1) has zero length or (2) is too long.

CVE-2014-0237

The cdf_unpack_summary_info function in cdf.c allows remote attackers to cause a denial of service (performance degradation) by triggering many file_printf calls.

CVE-2014-0207

The cdf_read_short_sector function in cdf.c allows remote attackers to cause a denial of service (assertion failure and application exit) via a crafted CDF file.

For Debian 6 Squeeze, these issues have been fixed in file version 5.04-5+squeeze6");

  script_tag(name:"affected", value:"'file' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"file", ver:"5.04-5+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagic-dev", ver:"5.04-5+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagic1", ver:"5.04-5+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-magic", ver:"5.04-5+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-magic-dbg", ver:"5.04-5+squeeze6", rls:"DEB6"))) {
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
