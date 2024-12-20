# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66181");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
  script_cve_id("CVE-2009-3379");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:1561");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(3|4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1561.

The libvorbis packages contain runtime libraries for use in programs that
support Ogg Vorbis. Ogg Vorbis is a fully open, non-proprietary, patent-and
royalty-free, general-purpose compressed audio format.

Multiple flaws were found in the libvorbis library. A specially-crafted Ogg
Vorbis media format file (Ogg) could cause an application using libvorbis
to crash or, possibly, execute arbitrary code when opened. (CVE-2009-3379)

Users of libvorbis should upgrade to these updated packages, which contain
backported patches to correct these issues. The desktop must be restarted
(log out, then log back in) for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1561.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#important");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libvorbis", rpm:"libvorbis~1.0~12.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvorbis-debuginfo", rpm:"libvorbis-debuginfo~1.0~12.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvorbis-devel", rpm:"libvorbis-devel~1.0~12.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvorbis", rpm:"libvorbis~1.1.0~3.el4_8.3", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvorbis-debuginfo", rpm:"libvorbis-debuginfo~1.1.0~3.el4_8.3", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvorbis-devel", rpm:"libvorbis-devel~1.1.0~3.el4_8.3", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvorbis", rpm:"libvorbis~1.1.2~3.el5_4.4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvorbis-debuginfo", rpm:"libvorbis-debuginfo~1.1.2~3.el5_4.4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvorbis-devel", rpm:"libvorbis-devel~1.1.2~3.el5_4.4", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
