# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:099 (openafs)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63914");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-05-05 16:00:35 +0200 (Tue, 05 May 2009)");
  script_cve_id("CVE-2009-1250", "CVE-2009-1251");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:099 (openafs)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0)");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in openafs:

The cache manager in the client in OpenAFS 1.0 through 1.4.8 and
1.5.0 through 1.5.58 on Linux allows remote attackers to cause a
denial of service (system crash) via an RX response with a large
error-code value that is interpreted as a pointer and dereferenced,
related to use of the ERR_PTR macro (CVE-2009-1250).

Heap-based buffer overflow in the cache manager in the client in
OpenAFS 1.0 through 1.4.8 and 1.5.0 through 1.5.58 on Unix platforms
allows remote attackers to cause a denial of service (system crash)
or possibly execute arbitrary code via an RX response containing
more data than specified in a request, related to use of XDR arrays
(CVE-2009-1251).

The updated packages have been patched to correct these issues.

Affected: 2008.1, 2009.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:099");
  script_tag(name:"summary", value:"The remote host is missing an update to openafs
announced via advisory MDVSA-2009:099.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"dkms-libafs", rpm:"dkms-libafs~1.4.6~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenafs1", rpm:"libopenafs1~1.4.6~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenafs-devel", rpm:"libopenafs-devel~1.4.6~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openafs", rpm:"openafs~1.4.6~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openafs-client", rpm:"openafs-client~1.4.6~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openafs-doc", rpm:"openafs-doc~1.4.6~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openafs-server", rpm:"openafs-server~1.4.6~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openafs1", rpm:"lib64openafs1~1.4.6~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openafs-devel", rpm:"lib64openafs-devel~1.4.6~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dkms-libafs", rpm:"dkms-libafs~1.4.7~5.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenafs1", rpm:"libopenafs1~1.4.7~5.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenafs-devel", rpm:"libopenafs-devel~1.4.7~5.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openafs", rpm:"openafs~1.4.7~5.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openafs-client", rpm:"openafs-client~1.4.7~5.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openafs-doc", rpm:"openafs-doc~1.4.7~5.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openafs-server", rpm:"openafs-server~1.4.7~5.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openafs1", rpm:"lib64openafs1~1.4.7~5.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openafs-devel", rpm:"lib64openafs-devel~1.4.7~5.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
