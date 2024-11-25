# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3988.1");
  script_cve_id("CVE-2024-9341", "CVE-2024-9407", "CVE-2024-9675", "CVE-2024-9676");
  script_tag(name:"creation_date", value:"2024-11-15 04:17:25 +0000 (Fri, 15 Nov 2024)");
  script_version("2024-11-15T15:55:05+0000");
  script_tag(name:"last_modification", value:"2024-11-15 15:55:05 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-15 16:15:06 +0000 (Tue, 15 Oct 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3988-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3988-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243988-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah' package(s) announced via the SUSE-SU-2024:3988-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for buildah fixes the following issues:

CVE-2024-9676: Fixed github.com/containers/storage: symlink traversal vulnerability in the containers/storage library can cause Denial of Service (DoS) (bsc#1231698):
CVE-2024-9675: VUL-0: CVE-2024-9675: buildah,podman: buildah: cache arbitrary directory mount (bsc#1231499):
CVE-2024-9407: Fixed improper input validation in bind-propagation Option of Dockerfile RUN --mount Instruction (bsc#1231208)

CVE-2024-9341: Fixed FIPS Crypto-Policy Directory Mounting Issue in containers/common Go Library (bsc#1231230)


Using networking slirp4netns as default instead of pasta on SLE (bsc#1232522).");

  script_tag(name:"affected", value:"'buildah' package(s) on SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.35.4~150400.3.33.1", rls:"SLES15.0SP4"))) {
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
