# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2024.3906");
  script_cve_id("CVE-2021-4181", "CVE-2021-4182", "CVE-2021-4184", "CVE-2021-4185", "CVE-2021-4186", "CVE-2021-4190", "CVE-2022-0581", "CVE-2022-0582", "CVE-2022-0583", "CVE-2022-0585", "CVE-2022-0586", "CVE-2022-3190", "CVE-2022-4344", "CVE-2022-4345", "CVE-2023-0411", "CVE-2023-0412", "CVE-2023-0413", "CVE-2023-0415", "CVE-2023-0416", "CVE-2023-0417", "CVE-2023-0666", "CVE-2023-0667", "CVE-2023-0668", "CVE-2023-1161", "CVE-2023-1992", "CVE-2023-1993", "CVE-2023-1994", "CVE-2023-2855", "CVE-2023-2856", "CVE-2023-2858", "CVE-2023-2879", "CVE-2023-2906", "CVE-2023-2952", "CVE-2023-3648", "CVE-2023-3649", "CVE-2023-4511", "CVE-2023-4512", "CVE-2023-4513", "CVE-2023-6175", "CVE-2024-0208", "CVE-2024-0209", "CVE-2024-0211", "CVE-2024-2955", "CVE-2024-4853", "CVE-2024-4854", "CVE-2024-8250", "CVE-2024-8645");
  script_tag(name:"creation_date", value:"2024-09-30 07:46:00 +0000 (Mon, 30 Sep 2024)");
  script_version("2024-10-01T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-10-01 05:06:07 +0000 (Tue, 01 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-23 18:07:47 +0000 (Wed, 23 Feb 2022)");

  script_name("Debian: Security Advisory (DLA-3906-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-3906-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2024/DLA-3906-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DLA-3906-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libwireshark-data", ver:"3.4.16-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwireshark-dev", ver:"3.4.16-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwireshark14", ver:"3.4.16-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwiretap-dev", ver:"3.4.16-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwiretap11", ver:"3.4.16-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwsutil-dev", ver:"3.4.16-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwsutil12", ver:"3.4.16-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tshark", ver:"3.4.16-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark", ver:"3.4.16-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-common", ver:"3.4.16-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-dev", ver:"3.4.16-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-doc", ver:"3.4.16-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-gtk", ver:"3.4.16-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-qt", ver:"3.4.16-0+deb11u1", rls:"DEB11"))) {
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
