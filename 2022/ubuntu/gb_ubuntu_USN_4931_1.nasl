# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2021.4931.1");
  script_cve_id("CVE-2020-14318", "CVE-2020-14323", "CVE-2020-14383", "CVE-2021-20254");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-24 18:30:42 +0000 (Thu, 24 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4931-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4931-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4931-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-4931-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Steven French discovered that Samba incorrectly handled ChangeNotify
permissions. A remote attacker could possibly use this issue to obtain file
name information. (CVE-2020-14318)

Bas Alberts discovered that Samba incorrectly handled certain winbind
requests. A remote attacker could possibly use this issue to cause winbind
to crash, resulting in a denial of service. (CVE-2020-14323)

Francis Brosnan Blazquez discovered that Samba incorrectly handled certain
invalid DNS records. A remote attacker could possibly use this issue to
cause the DNS server to crash, resulting in a denial of service.
(CVE-2020-14383)

Peter Eriksson discovered that Samba incorrectly handled certain negative
idmap cache entries. This issue could result in certain users gaining
unauthorized access to files, contrary to expected behaviour.
(CVE-2021-20254)");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.3.11+dfsg-0ubuntu0.14.04.20+esm11", rls:"UBUNTU14.04 LTS"))) {
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
