# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.175.1");
  script_cve_id("CVE-2005-2496");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-175-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-175-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-175-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the USN-175-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Thomas Biege discovered a flaw in the privilege dropping of the NTP
server. When ntpd was configured to drop root privileges, and the
group to run under was specified as a name (as opposed to a numeric
group ID), ntpd changed to the wrong group. Depending on the actual
group it changed to, this could either cause non-minimal privileges,
or a malfunctioning ntp server if the group does not have the
privileges that ntpd actually needs.

On Ubuntu 4.10, ntpd does not use privilege dropping by default, so
you are only affected if you manually activated it. In Ubuntu 5.04,
privilege dropping is used by default, but this bug is already fixed.");

  script_tag(name:"affected", value:"'ntp' package(s) on Ubuntu 4.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ntp", ver:"4.2.0a-10ubuntu2.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntp-doc", ver:"4.2.0a-10ubuntu2.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntp-refclock", ver:"4.2.0a-10ubuntu2.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntp-server", ver:"4.2.0a-10ubuntu2.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntp-simple", ver:"4.2.0a-10ubuntu2.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntpdate", ver:"4.2.0a-10ubuntu2.1", rls:"UBUNTU4.10"))) {
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
