# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1482");
  script_cve_id("CVE-2020-15157", "CVE-2021-32760");
  script_tag(name:"creation_date", value:"2022-04-20 04:26:03 +0000 (Wed, 20 Apr 2022)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-28 17:31:54 +0000 (Wed, 28 Jul 2021)");

  script_name("Huawei EulerOS: Security Advisory for docker-engine (EulerOS-SA-2022-1482)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1482");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2022-1482");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'docker-engine' package(s) announced via the EulerOS-SA-2022-1482 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In containerd (an industry-standard container runtime) before version 1.2.14 there is a credential leaking vulnerability. If a container image manifest in the OCI Image format or Docker Image V2 Schema 2 format includes a URL for the location of a specific image layer (otherwise known as a 'foreign layer'), the default containerd resolver will follow that URL to attempt to download it. In v1.2.x but not 1.3.0 or later, the default containerd resolver will provide its authentication credentials if the server where the URL is located presents an HTTP 401 status code along with registry-specific HTTP headers. If an attacker publishes a public image with a manifest that directs one of the layers to be fetched from a web server they control and they trick a user or system into pulling the image, they can obtain the credentials used for pulling that image. In some cases, this may be the user's username and password for the registry. In other cases, this may be the credentials attached to the cloud virtual instance which can grant access to other cloud resources in the account. The default containerd resolver is used by the cri-containerd plugin (which can be used by Kubernetes), the ctr development tool, and other client programs that have explicitly linked against it. This vulnerability has been fixed in containerd 1.2.14. containerd 1.3 and later are not affected. If you are using containerd 1.3 or later, you are not affected. If you are using cri-containerd in the 1.2 series or prior, you should ensure you only pull images from trusted sources. Other container runtimes built on top of containerd but not using the default resolver (such as Docker) are not affected.(CVE-2020-15157)

containerd is a container runtime. A bug was found in containerd versions prior to 1.4.8 and 1.5.4 where pulling and extracting a specially-crafted container image can result in Unix file permission changes for existing files in the host's filesystem. Changes to file permissions can deny access to the expected owner of the file, widen access to others, or set extended bits like setuid, setgid, and sticky. This bug does not directly allow files to be read, modified, or executed without an additional cooperating process. This bug has been fixed in containerd 1.5.4 and 1.4.8. As a workaround, ensure that users only pull images from trusted sources. Linux security modules (LSMs) like SELinux and AppArmor can limit the files potentially affected by this bug through policies and profiles that prevent containerd from interacting with specific files.(CVE-2021-32760)");

  script_tag(name:"affected", value:"'docker-engine' package(s) on Huawei EulerOS V2.0SP10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod", value:"30");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"docker-engine", rpm:"docker-engine~18.09.0.200~200.h41.25.14.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-engine-selinux", rpm:"docker-engine-selinux~18.09.0.200~200.h41.25.14.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
