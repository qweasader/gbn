# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.2347");
  script_cve_id("CVE-2018-10904", "CVE-2018-10907", "CVE-2018-10913", "CVE-2018-10914", "CVE-2018-10923", "CVE-2018-10926", "CVE-2018-10927", "CVE-2018-10928", "CVE-2018-10929", "CVE-2018-10930");
  script_tag(name:"creation_date", value:"2020-11-04 08:53:16 +0000 (Wed, 04 Nov 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-12 18:33:00 +0000 (Tue, 12 Apr 2022)");

  script_name("Huawei EulerOS: Security Advisory for glusterfs (EulerOS-SA-2020-2347)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-2347");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2347");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'glusterfs' package(s) announced via the EulerOS-SA-2020-2347 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that glusterfs server does not properly sanitize file paths in the 'trusted.io-stats-dump' extended attribute which is used by the 'debug/io-stats' translator. Attacker can use this flaw to create files and execute arbitrary code. To exploit this attacker would require sufficient access to modify the extended attributes of files on a gluster volume.(CVE-2018-10904)

It was found that glusterfs server is vulnerable to multiple stack based buffer overflows due to functions in server-rpc-fopc.c allocating fixed size buffers using 'alloca(3)'. An authenticated attacker could exploit this by mounting a gluster volume and sending a string longer that the fixed buffer size to cause crash or potential code execution.(CVE-2018-10907)

An information disclosure vulnerability was discovered in glusterfs server. An attacker could issue a xattr request via glusterfs FUSE to determine the existence of any file.(CVE-2018-10913)

It was found that an attacker could issue a xattr request via glusterfs FUSE to cause gluster brick process to crash which will result in a remote denial of service. If gluster multiplexing is enabled this will result in a crash of multiple bricks and gluster volumes.(CVE-2018-10914)

It was found that the 'mknod' call derived from mknod(2) can create files pointing to devices on a glusterfs server node. An authenticated attacker could use this to create an arbitrary device and read data from any device attached to the glusterfs server node.(CVE-2018-10923)

A flaw was found in RPC request using gfs3_mknod_req supported by glusterfs server. An authenticated attacker could use this flaw to write files to an arbitrary location via path traversal and execute arbitrary code on a glusterfs server node.(CVE-2018-10926)

A flaw was found in RPC request using gfs3_lookup_req in glusterfs server. An authenticated attacker could use this flaw to leak information and execute remote denial of service by crashing gluster brick process.(CVE-2018-10927)

A flaw was found in RPC request using gfs3_symlink_req in glusterfs server which allows symlink destinations to point to file paths outside of the gluster volume. An authenticated attacker could use this flaw to create arbitrary symlinks pointing anywhere on the server and execute arbitrary code on glusterfs server nodes.(CVE-2018-10928)

A flaw was found in RPC request using gfs2_create_req in glusterfs server. An authenticated attacker could use this flaw to create arbitrary files and execute arbitrary code on glusterfs server nodes.(CVE-2018-10929)

A flaw was found in RPC request using gfs3_rename_req in glusterfs server. An authenticated attacker could use this flaw to write to a destination outside the gluster volume.(CVE-2018-10930)");

  script_tag(name:"affected", value:"'glusterfs' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"glusterfs", rpm:"glusterfs~3.7.1~16.0.1.h2", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-api", rpm:"glusterfs-api~3.7.1~16.0.1.h2", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-client-xlators", rpm:"glusterfs-client-xlators~3.7.1~16.0.1.h2", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-fuse", rpm:"glusterfs-fuse~3.7.1~16.0.1.h2", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-libs", rpm:"glusterfs-libs~3.7.1~16.0.1.h2", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-rdma", rpm:"glusterfs-rdma~3.7.1~16.0.1.h2", rls:"EULEROS-2.0SP2"))) {
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
