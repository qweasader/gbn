# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2418");
  script_cve_id("CVE-2021-47183", "CVE-2021-47236", "CVE-2021-47261", "CVE-2021-47265", "CVE-2021-47275", "CVE-2021-47277", "CVE-2021-47280", "CVE-2021-47301", "CVE-2021-47311", "CVE-2021-47329", "CVE-2021-47353", "CVE-2021-47354", "CVE-2021-47391", "CVE-2021-47397", "CVE-2021-47408", "CVE-2021-47425", "CVE-2021-47427", "CVE-2021-47435", "CVE-2021-47438", "CVE-2021-47455", "CVE-2021-47466", "CVE-2021-47469", "CVE-2021-47473", "CVE-2021-47478", "CVE-2021-47480", "CVE-2021-47483", "CVE-2021-47495", "CVE-2021-47498", "CVE-2021-47501", "CVE-2021-47516", "CVE-2021-47541", "CVE-2021-47548", "CVE-2021-47565", "CVE-2021-47597", "CVE-2021-47609", "CVE-2021-47619", "CVE-2022-48695", "CVE-2022-48708", "CVE-2022-48715", "CVE-2022-48744", "CVE-2022-48747", "CVE-2022-48804", "CVE-2022-48855", "CVE-2023-52623", "CVE-2023-52653", "CVE-2023-52656", "CVE-2023-52679", "CVE-2023-52698", "CVE-2023-52703", "CVE-2023-52708", "CVE-2023-52739", "CVE-2023-52752", "CVE-2023-52796", "CVE-2023-52803", "CVE-2023-52813", "CVE-2023-52831", "CVE-2023-52835", "CVE-2023-52843", "CVE-2023-52868", "CVE-2023-52881", "CVE-2024-25739", "CVE-2024-26846", "CVE-2024-26880", "CVE-2024-27020", "CVE-2024-27062", "CVE-2024-27388", "CVE-2024-35789", "CVE-2024-35805", "CVE-2024-35807", "CVE-2024-35808", "CVE-2024-35809", "CVE-2024-35815", "CVE-2024-35823", "CVE-2024-35835", "CVE-2024-35847", "CVE-2024-35886", "CVE-2024-35888", "CVE-2024-35896", "CVE-2024-35904", "CVE-2024-35910", "CVE-2024-35922", "CVE-2024-35925", "CVE-2024-35930", "CVE-2024-35955", "CVE-2024-35960", "CVE-2024-35962", "CVE-2024-35969", "CVE-2024-35984", "CVE-2024-35995", "CVE-2024-35997", "CVE-2024-36004", "CVE-2024-36016", "CVE-2024-36883", "CVE-2024-36901", "CVE-2024-36902", "CVE-2024-36903", "CVE-2024-36904", "CVE-2024-36905", "CVE-2024-36917", "CVE-2024-36919", "CVE-2024-36924", "CVE-2024-36940", "CVE-2024-36952", "CVE-2024-36971", "CVE-2024-37353", "CVE-2024-37356", "CVE-2024-38538", "CVE-2024-38541", "CVE-2024-38559", "CVE-2024-38588", "CVE-2024-38596", "CVE-2024-38601", "CVE-2024-39276", "CVE-2024-39480", "CVE-2024-39487", "CVE-2024-39494", "CVE-2024-40904", "CVE-2024-40960", "CVE-2024-40984", "CVE-2024-40995", "CVE-2024-40998", "CVE-2024-41005", "CVE-2024-41007");
  script_tag(name:"creation_date", value:"2024-09-12 08:10:51 +0000 (Thu, 12 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 19:17:25 +0000 (Wed, 24 Jul 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2418)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2418");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2418");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2418 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel: scsi: core: Put LLD module refcnt after SCSI device is released(CVE-2021-47480)

kernel: dm rq: don't queue request to blk-mq during DM suspend(CVE-2021-47498)

kernel: dm: fix mempool NULL pointer race when completing IO(CVE-2021-47435)

kernel: fs/aio: Check IOCB_AIO_RW before the struct aio_kiocb conversion(CVE-2024-35815)

kernel: io_uring: drop any code related to SCM_RIGHTS(CVE-2023-52656)

kernel: cpu/hotplug: Don't offline the last non-isolated CPU(CVE-2023-52831)

kernel: drm/sched: Avoid data corruptions(CVE-2021-47354)

kernel: IB/mlx5: Fix initializing CQ fragments buffer(CVE-2021-47261)

kernel: drm: Fix use-after-free read in drm_getunique()(CVE-2021-47280)

kernel: selinux: avoid dereference of garbage after mount failure(CVE-2024-35904)

kernel: scsi: qla2xxx: Fix a memory leak in an error path of qla2x00_process_els()(CVE-2021-47473)

kernel: mmc: mmc_spi: fix error handling in mmc_spi_probe()(CVE-2023-52708)

kernel: block: fix overflow in blk_ioctl_discard()(CVE-2024-36917)

kernel: PCI/PM: Drain runtime-idle callbacks before driver removal(CVE-2024-35809)

kernel: crypto: pcrypt - Fix hungtask for PADATA_RESET(CVE-2023-52813)

kernel: bcache: avoid oversized read request in cache missing code path(CVE-2021-47275)

kernel: thermal: core: prevent potential string overflow(CVE-2023-52868)

kernel: udf: Fix NULL pointer dereference in udf_symlink function(CVE-2021-47353)

kernel: pinctrl: core: delete incorrect free in pinctrl_enable()(CVE-2024-36940)

kernel: wifi: mac80211: check/clear fast rx for non-4addr sta VLAN changes(CVE-2024-35789)

kernel: netfilter: conntrack: serialize hash resizes and cleanups(CVE-2021-47408)

kernel: scsi: mpt3sas: Fix kernel panic during drive powercycle test(CVE-2021-47565)

kernel: fbmon: prevent division by zero in fb_videomode_from_videomode()(CVE-2024-35922)

kernel: isofs: Fix out of bound access for corrupted isofs image(CVE-2021-47478)

kernel: ext4: fix corruption during on-line resize(CVE-2024-35807)

kernel: scsi: bnx2fc: Remove spin_lock_bh while releasing resources after upload(CVE-2024-36919)

kernel: perf/core: Bail out early if the request AUX area is out of bound(CVE-2023-52835)

kernel: md/dm-raid: don&#39,t call md_reap_sync_thread() directly(CVE-2024-35808)

kernel: scsi: bnx2fc: Make bnx2fc_recv_frame() mp safe(CVE-2022-48715)

kernel: Fix page corruption caused by racy check in __free_pages(CVE-2023-52739)

kernel: mm, slub: fix potential memoryleak in kmem_cache_open()(CVE-2021-47466)

kernel: ext4: fix mb_cache_entry&#39,s e_refcnt leak in ext4_xattr_block_cache_find()(CVE-2024-39276)

kernel: scsi: lpfc: Move NPIV's transport unregistration to after resource clean up(CVE-2024-36952)

kernel: scsi: mpt3sas: Fix use-after-free warning(CVE-2022-48695)

kernel: smb: client: fix use-after-free bug in cifs_debug_data_proc_show()(CVE-2023-52752)

kernel:fix lockup in dm_exception_table_exit There ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2211.3.0.h1867.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.19.90~vhulk2211.3.0.h1867.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2211.3.0.h1867.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2211.3.0.h1867.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2211.3.0.h1867.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
