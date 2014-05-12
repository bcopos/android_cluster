--- a/mm/vmscan.c
+++ b/mm/vmscan.c
@@ -48,6 +48,12 @@
 
 #include "internal.h"
 
+#ifdef CONFIG_KRG_MM
+#include <net/krgrpc/rpc.h>
+#endif
+
+#define RPC_MAX_PAGES 1700
+
 struct scan_control {
 	/* Incremented by the number of inactive pages that were scanned */
 	unsigned long nr_scanned;
@@ -91,7 +97,11 @@ struct scan_control {
 	unsigned long (*isolate_pages)(unsigned long nr, struct list_head *dst,
 			unsigned long *scanned, int order, int mode,
 			struct zone *z, struct mem_cgroup *mem_cont,
+#ifdef CONFIG_KRG_MM
+			int active, int file, int kddm);
+#else
 			int active, int file);
+#endif
 };
 
 #define lru_to_page(_head) (list_entry((_head)->prev, struct page, lru))
@@ -534,6 +544,10 @@ redo:
 		 * We know how to handle that.
 		 */
 		lru = active + page_is_file_cache(page);
+#ifdef CONFIG_KRG_MM
+		BUG_ON(page_is_migratable(page) && page_is_file_cache(page));
+		lru += page_is_migratable(page);
+#endif
 		lru_cache_add_lru(page, lru);
 	} else {
 		/*
@@ -576,11 +590,36 @@ void putback_lru_page(struct page *page)
 	VM_BUG_ON(PageLRU(page));
 
 	lru = !!TestClearPageActive(page) + page_is_file_cache(page);
+#ifdef CONFIG_KRG_MM
+	BUG_ON(page_is_migratable(page) && page_is_file_cache(page));
+	lru += page_is_migratable(page);
+#endif
 	lru_cache_add_lru(page, lru);
 	put_page(page);
 }
 #endif /* CONFIG_UNEVICTABLE_LRU */
 
+#ifdef CONFIG_KRG_MM
+static int check_injection_flow(void)
+{
+	long i = 0, limit = RPC_MAX_PAGES;
+
+	if ((rpc_consumed_bytes() / PAGE_SIZE) < limit)
+		return 0;
+
+	if (current_is_kswapd())
+		limit = limit / 2;
+	else
+		limit = 4 * limit / 5;
+
+	while ((rpc_consumed_bytes() / PAGE_SIZE) > limit) {
+		schedule();
+		i++;
+	}
+
+	return 0;
+}
+#endif
 
 /*
  * shrink_page_list() returns the number of reclaimed pages
@@ -608,6 +647,11 @@ static unsigned long shrink_page_list(struct list_head *page_list,
 		page = lru_to_page(page_list);
 		list_del(&page->lru);
 
+#ifdef CONFIG_KRG_MM
+		if (PageMigratable(page))
+			check_injection_flow();
+#endif
+
 		if (!trylock_page(page))
 			goto keep;
 
@@ -649,6 +693,35 @@ static unsigned long shrink_page_list(struct list_head *page_list,
 					referenced && page_mapping_inuse(page))
 			goto activate_locked;
 
+#ifdef CONFIG_KRG_MM
+		if (PageMigratable(page) && (page_mapped(page))) {
+			switch (try_to_flush_page(page)) {
+			case SWAP_FAIL:
+				goto activate_locked;
+                        case SWAP_AGAIN:
+                                goto keep_locked;
+			case SWAP_MLOCK:
+				goto cull_mlocked;
+			case SWAP_FLUSH_FAIL:
+				BUG(); /* TODO: Try a swap on disk */
+                        case SWAP_SUCCESS:
+                                ; /* try to free the page below */
+                        }
+
+			/*
+			 *  TODO: check this code. We can probably
+			 *  Reuse the code below in the
+			 *  page_has_private if section.
+			 */
+			unlock_page(page);
+			if (put_page_testzero(page))
+				goto free_it;
+			printk ("WARNING: page %p has count %d\n", page,
+				page_count(page));
+			nr_reclaimed++;
+			continue;
+		}
+#endif
 		/*
 		 * Anonymous process memory has backing store?
 		 * Try to allocate it some swap space here.
@@ -733,6 +806,9 @@ static unsigned long shrink_page_list(struct list_head *page_list,
 		 * Otherwise, leave the page on the LRU so it is swappable.
 		 */
 		if (page_has_private(page)) {
+#ifdef CONFIG_KRG_MM
+			BUG_ON (page->obj_entry);
+#endif
 			if (!try_to_release_page(page, sc->gfp_mask))
 				goto activate_locked;
 			if (!mapping && page_count(page) == 1) {
@@ -968,13 +1044,21 @@ static unsigned long isolate_pages_global(unsigned long nr,
 					unsigned long *scanned, int order,
 					int mode, struct zone *z,
 					struct mem_cgroup *mem_cont,
+#ifdef CONFIG_KRG_MM
+					int active, int file, int kddm)
+#else
 					int active, int file)
+#endif
 {
 	int lru = LRU_BASE;
 	if (active)
 		lru += LRU_ACTIVE;
 	if (file)
 		lru += LRU_FILE;
+#ifdef CONFIG_KRG_MM
+	if (kddm)
+		lru += LRU_MIGR;
+#endif
 	return isolate_lru_pages(nr, &z->lru[lru].list, dst, scanned, order,
 								mode, !!file);
 }
@@ -992,6 +1076,10 @@ static unsigned long clear_active_flags(struct list_head *page_list,
 
 	list_for_each_entry(page, page_list, lru) {
 		lru = page_is_file_cache(page);
+#ifdef CONFIG_KRG_MM
+		BUG_ON(page_is_migratable(page) && page_is_file_cache(page));
+		lru += page_is_migratable(page);
+#endif
 		if (PageActive(page)) {
 			lru += LRU_ACTIVE;
 			ClearPageActive(page);
@@ -1054,7 +1142,11 @@ int isolate_lru_page(struct page *page)
  */
 static unsigned long shrink_inactive_list(unsigned long max_scan,
 			struct zone *zone, struct scan_control *sc,
+#ifdef CONFIG_KRG_MM
+			int priority, int file, int kddm)
+#else
 			int priority, int file)
+#endif
 {
 	LIST_HEAD(page_list);
 	struct pagevec pvec;
@@ -1089,7 +1181,11 @@ static unsigned long shrink_inactive_list(unsigned long max_scan,
 
 		nr_taken = sc->isolate_pages(sc->swap_cluster_max,
 			     &page_list, &nr_scan, sc->order, mode,
+#ifdef CONFIG_KRG_MM
+				zone, sc->mem_cgroup, 0, file, kddm);
+#else
 				zone, sc->mem_cgroup, 0, file);
+#endif
 		nr_active = clear_active_flags(&page_list, count);
 		__count_vm_events(PGDEACTIVATE, nr_active);
 
@@ -1101,6 +1197,12 @@ static unsigned long shrink_inactive_list(unsigned long max_scan,
 						-count[LRU_ACTIVE_ANON]);
 		__mod_zone_page_state(zone, NR_INACTIVE_ANON,
 						-count[LRU_INACTIVE_ANON]);
+#ifdef CONFIG_KRG_MM
+		__mod_zone_page_state(zone, NR_ACTIVE_MIGR,
+						-count[LRU_ACTIVE_MIGR]);
+		__mod_zone_page_state(zone, NR_INACTIVE_MIGR,
+						-count[LRU_INACTIVE_MIGR]);
+#endif
 
 		if (scanning_global_lru(sc))
 			zone->pages_scanned += nr_scan;
@@ -1109,6 +1211,10 @@ static unsigned long shrink_inactive_list(unsigned long max_scan,
 		reclaim_stat->recent_scanned[0] += count[LRU_ACTIVE_ANON];
 		reclaim_stat->recent_scanned[1] += count[LRU_INACTIVE_FILE];
 		reclaim_stat->recent_scanned[1] += count[LRU_ACTIVE_FILE];
+#ifdef CONFIG_KRG_MM
+		reclaim_stat->recent_scanned[2] += count[LRU_INACTIVE_MIGR];
+		reclaim_stat->recent_scanned[2] += count[LRU_ACTIVE_MIGR];
+#endif
 
 		spin_unlock_irq(&zone->lru_lock);
 
@@ -1168,7 +1274,11 @@ static unsigned long shrink_inactive_list(unsigned long max_scan,
 			lru = page_lru(page);
 			add_page_to_lru_list(zone, page, lru);
 			if (PageActive(page)) {
+#ifdef CONFIG_KRG_MM
+				int file = reclaim_stat_index (page);
+#else
 				int file = !!page_is_file_cache(page);
+#endif
 				reclaim_stat->recent_rotated[file]++;
 			}
 			if (!pagevec_add(&pvec, page)) {
@@ -1219,7 +1329,11 @@ static inline void note_zone_scanning_priority(struct zone *zone, int priority)
 
 
 static void shrink_active_list(unsigned long nr_pages, struct zone *zone,
+#ifdef CONFIG_KRG_MM
+		struct scan_control *sc, int priority, int file, int kddm)
+#else
 			struct scan_control *sc, int priority, int file)
+#endif
 {
 	unsigned long pgmoved;
 	int pgdeactivate = 0;
@@ -1235,7 +1349,11 @@ static void shrink_active_list(unsigned long nr_pages, struct zone *zone,
 	spin_lock_irq(&zone->lru_lock);
 	pgmoved = sc->isolate_pages(nr_pages, &l_hold, &pgscanned, sc->order,
 					ISOLATE_ACTIVE, zone,
+#ifdef CONFIG_KRG_MM
+					sc->mem_cgroup, 1, file, kddm);
+#else
 					sc->mem_cgroup, 1, file);
+#endif
 	/*
 	 * zone->pages_scanned is used for detect zone's oom
 	 * mem_cgroup remembers nr_scan by itself.
@@ -1243,14 +1361,25 @@ static void shrink_active_list(unsigned long nr_pages, struct zone *zone,
 	if (scanning_global_lru(sc)) {
 		zone->pages_scanned += pgscanned;
 	}
+#ifdef CONFIG_KRG_MM
+	reclaim_stat->recent_scanned[RECLAIM_STAT_INDEX(file, kddm)] += pgmoved;
+#else
 	reclaim_stat->recent_scanned[!!file] += pgmoved;
+#endif
 
 	if (file)
 		__mod_zone_page_state(zone, NR_ACTIVE_FILE, -pgmoved);
 	else
+#ifdef CONFIG_KRG_MM
+	if (kddm)
+		__mod_zone_page_state(zone, NR_ACTIVE_MIGR, -pgmoved);
+	else
+#endif
 		__mod_zone_page_state(zone, NR_ACTIVE_ANON, -pgmoved);
 	spin_unlock_irq(&zone->lru_lock);
 
+
+
 	pgmoved = 0;
 	while (!list_empty(&l_hold)) {
 		cond_resched();
@@ -1274,7 +1403,11 @@ static void shrink_active_list(unsigned long nr_pages, struct zone *zone,
 	 * Move the pages to the [file or anon] inactive list.
 	 */
 	pagevec_init(&pvec, 1);
+#ifdef CONFIG_KRG_MM
+	lru = BUILD_LRU_ID(0 /* inactive */, file, kddm);
+#else
 	lru = LRU_BASE + file * LRU_FILE;
+#endif
 
 	spin_lock_irq(&zone->lru_lock);
 	/*
@@ -1283,7 +1416,11 @@ static void shrink_active_list(unsigned long nr_pages, struct zone *zone,
 	 * This helps balance scan pressure between file and anonymous
 	 * pages in get_scan_ratio.
 	 */
+#ifdef CONFIG_KRG_MM
+	reclaim_stat->recent_rotated[RECLAIM_STAT_INDEX(file, kddm)] += pgmoved;
+#else
 	reclaim_stat->recent_rotated[!!file] += pgmoved;
+#endif
 
 	pgmoved = 0;
 	while (!list_empty(&l_inactive)) {
@@ -1350,21 +1487,65 @@ static int inactive_anon_is_low(struct zone *zone, struct scan_control *sc)
 	return low;
 }
 
+#ifdef CONFIG_KRG_MM
+static int inactive_kddm_is_low_global(struct zone *zone)
+{
+	unsigned long active, inactive;
+
+	active = zone_page_state(zone, NR_ACTIVE_MIGR);
+	inactive = zone_page_state(zone, NR_INACTIVE_MIGR);
+
+	if (inactive * zone->inactive_ratio < active)
+		return 1;
+
+	return 0;
+}
+
+static int inactive_kddm_is_low(struct zone *zone, struct scan_control *sc)
+{
+	int low;
+
+	if (scanning_global_lru(sc))
+		low = inactive_kddm_is_low_global(zone);
+	else
+		BUG();
+	return low;
+}
+#endif
+
 static unsigned long shrink_list(enum lru_list lru, unsigned long nr_to_scan,
 	struct zone *zone, struct scan_control *sc, int priority)
 {
 	int file = is_file_lru(lru);
 
 	if (lru == LRU_ACTIVE_FILE) {
+#ifdef CONFIG_KRG_MM
+		shrink_active_list(nr_to_scan, zone, sc, priority, file, 0);
+#else
 		shrink_active_list(nr_to_scan, zone, sc, priority, file);
+#endif
 		return 0;
 	}
 
 	if (lru == LRU_ACTIVE_ANON && inactive_anon_is_low(zone, sc)) {
+#ifdef CONFIG_KRG_MM
+		shrink_active_list(nr_to_scan, zone, sc, priority, file, 0);
+#else
 		shrink_active_list(nr_to_scan, zone, sc, priority, file);
+#endif
 		return 0;
 	}
+#ifdef CONFIG_KRG_MM
+	if (lru == LRU_ACTIVE_MIGR && inactive_kddm_is_low(zone, sc)) {
+		shrink_active_list(nr_to_scan, zone, sc, priority, 0, 1);
+		return 0;
+	}
+
+	return shrink_inactive_list(nr_to_scan, zone, sc, priority, file,
+				    is_kddm_lru(lru));
+#else
 	return shrink_inactive_list(nr_to_scan, zone, sc, priority, file);
+#endif
 }
 
 /*
@@ -1379,23 +1560,31 @@ static unsigned long shrink_list(enum lru_list lru, unsigned long nr_to_scan,
 static void get_scan_ratio(struct zone *zone, struct scan_control *sc,
 					unsigned long *percent)
 {
+#ifdef CONFIG_KRG_MM
+	unsigned long kddm, kddm_prio, kp;
+#endif
 	unsigned long anon, file, free;
 	unsigned long anon_prio, file_prio;
 	unsigned long ap, fp;
 	struct zone_reclaim_stat *reclaim_stat = get_reclaim_stat(zone, sc);
 
+#ifndef CONFIG_KRG_MM
 	/* If we have no swap space, do not bother scanning anon pages. */
 	if (!sc->may_swap || (nr_swap_pages <= 0)) {
 		percent[0] = 0;
 		percent[1] = 100;
 		return;
 	}
+#endif
 
 	anon  = zone_nr_pages(zone, sc, LRU_ACTIVE_ANON) +
 		zone_nr_pages(zone, sc, LRU_INACTIVE_ANON);
 	file  = zone_nr_pages(zone, sc, LRU_ACTIVE_FILE) +
 		zone_nr_pages(zone, sc, LRU_INACTIVE_FILE);
-
+#ifdef CONFIG_KRG_MM
+	kddm  = zone_nr_pages(zone, sc, LRU_ACTIVE_MIGR) +
+		zone_nr_pages(zone, sc, LRU_INACTIVE_MIGR);
+#else
 	if (scanning_global_lru(sc)) {
 		free  = zone_page_state(zone, NR_FREE_PAGES);
 		/* If we have very few page cache pages,
@@ -1406,7 +1595,7 @@ static void get_scan_ratio(struct zone *zone, struct scan_control *sc,
 			return;
 		}
 	}
-
+#endif
 	/*
 	 * OK, so we have swap space and a fair amount of page cache
 	 * pages.  We use the recently rotated / recently scanned
@@ -1432,13 +1621,33 @@ static void get_scan_ratio(struct zone *zone, struct scan_control *sc,
 		spin_unlock_irq(&zone->lru_lock);
 	}
 
+#ifdef CONFIG_KRG_MM
+	if (unlikely(reclaim_stat->recent_scanned[2] > kddm / 4)) {
+		spin_lock_irq(&zone->lru_lock);
+		reclaim_stat->recent_scanned[2] /= 2;
+		reclaim_stat->recent_rotated[2] /= 2;
+		spin_unlock_irq(&zone->lru_lock);
+	}
+#endif
+
 	/*
 	 * With swappiness at 100, anonymous and file have the same priority.
 	 * This scanning priority is essentially the inverse of IO cost.
 	 */
 	anon_prio = sc->swappiness;
 	file_prio = 200 - sc->swappiness;
-
+#ifdef CONFIG_KRG_MM
+	if (!sc->may_swap || (nr_swap_pages <= 0))
+		anon_prio = 0;
+	if (scanning_global_lru(sc)) {
+		free  = zone_page_state(zone, NR_FREE_PAGES);
+		/* If we have very few page cache pages,
+		   force-scan anon pages. */
+		if (unlikely(file + free <= zone->pages_high))
+			file_prio = 0;
+	}
+	kddm_prio = 400 - anon_prio - file_prio;
+#endif
 	/*
 	 * The amount of pressure on anon vs file pages is inversely
 	 * proportional to the fraction of recently scanned pages on
@@ -1450,9 +1659,20 @@ static void get_scan_ratio(struct zone *zone, struct scan_control *sc,
 	fp = (file_prio + 1) * (reclaim_stat->recent_scanned[1] + 1);
 	fp /= reclaim_stat->recent_rotated[1] + 1;
 
+#ifdef CONFIG_KRG_MM
+	kp = (kddm_prio + 1) * (reclaim_stat->recent_scanned[2] + 1);
+	kp /= reclaim_stat->recent_rotated[2] + 1;
+
+	/* Normalize to percentages */
+	percent[0] = 100 * ap / (ap + fp + kp + 1);
+	percent[1] = 100 * fp / (ap + fp + kp + 1);
+	percent[2] = 100 - percent[0] - percent[1];
+#else
+
 	/* Normalize to percentages */
 	percent[0] = 100 * ap / (ap + fp + 1);
 	percent[1] = 100 - percent[0];
+#endif
 }
 
 
@@ -1464,7 +1684,11 @@ static void shrink_zone(int priority, struct zone *zone,
 {
 	unsigned long nr[NR_LRU_LISTS];
 	unsigned long nr_to_scan;
+#ifdef CONFIG_KRG_MM
+	unsigned long percent[3];	/* anon @ 0; file @ 1; kddm @ 2 */
+#else
 	unsigned long percent[2];	/* anon @ 0; file @ 1 */
+#endif
 	enum lru_list l;
 	unsigned long nr_reclaimed = sc->nr_reclaimed;
 	unsigned long swap_cluster_max = sc->swap_cluster_max;
@@ -1472,7 +1696,11 @@ static void shrink_zone(int priority, struct zone *zone,
 	get_scan_ratio(zone, sc, percent);
 
 	for_each_evictable_lru(l) {
+#ifdef CONFIG_KRG_MM
+		int file = RECLAIM_STAT_INDEX(is_file_lru(l), is_kddm_lru(l));
+#else
 		int file = is_file_lru(l);
+#endif
 		unsigned long scan;
 
 		scan = zone_nr_pages(zone, sc, l);
@@ -1492,7 +1720,11 @@ static void shrink_zone(int priority, struct zone *zone,
 	}
 
 	while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_FILE] ||
+#ifdef CONFIG_KRG_MM
+	       nr[LRU_INACTIVE_MIGR] || nr[LRU_INACTIVE_FILE]) {
+#else
 					nr[LRU_INACTIVE_FILE]) {
+#endif
 		for_each_evictable_lru(l) {
 			if (nr[l]) {
 				nr_to_scan = min(nr[l], swap_cluster_max);
@@ -1522,7 +1754,13 @@ static void shrink_zone(int priority, struct zone *zone,
 	 * rebalance the anon lru active/inactive ratio.
 	 */
 	if (inactive_anon_is_low(zone, sc))
+#ifdef CONFIG_KRG_MM
+		shrink_active_list(SWAP_CLUSTER_MAX, zone, sc, priority, 0, 0);
+	if (inactive_kddm_is_low(zone, sc))
+		shrink_active_list(SWAP_CLUSTER_MAX, zone, sc, priority, 0, 1);
+#else
 		shrink_active_list(SWAP_CLUSTER_MAX, zone, sc, priority, 0);
+#endif
 
 	throttle_vm_writeout(sc->gfp_mask);
 }
@@ -1823,7 +2061,15 @@ loop_again:
 			 */
 			if (inactive_anon_is_low(zone, &sc))
 				shrink_active_list(SWAP_CLUSTER_MAX, zone,
+#ifndef CONFIG_KRG_MM
 							&sc, priority, 0);
+#else
+							&sc, priority, 0, 0);
+			/* Do the same on kddm lru pages */
+			if (inactive_kddm_is_low(zone, &sc))
+				shrink_active_list(SWAP_CLUSTER_MAX, zone,
+						   &sc, priority, 0, 1);
+#endif
 
 			if (!zone_watermark_ok(zone, order, zone->pages_high,
 					       0, 0)) {
@@ -2052,6 +2298,10 @@ unsigned long global_lru_pages(void)
 {
 	return global_page_state(NR_ACTIVE_ANON)
 		+ global_page_state(NR_ACTIVE_FILE)
+#ifdef CONFIG_KRG_MM
+		+ global_page_state(NR_ACTIVE_MIGR)
+		+ global_page_state(NR_INACTIVE_MIGR)
+#endif
 		+ global_page_state(NR_INACTIVE_ANON)
 		+ global_page_state(NR_INACTIVE_FILE);
 }
@@ -2465,6 +2715,10 @@ retry:
 	if (page_evictable(page, NULL)) {
 		enum lru_list l = LRU_INACTIVE_ANON + page_is_file_cache(page);
 
+#ifdef CONFIG_KRG_MM
+		BUG_ON(page_is_migratable(page) && page_is_file_cache(page));
+		l += page_is_migratable(page);
+#endif
 		__dec_zone_state(zone, NR_UNEVICTABLE);
 		list_move(&page->lru, &zone->lru[l].list);
 		mem_cgroup_move_lists(page, LRU_UNEVICTABLE, l);
diff --git a/mm/vmstat.c b/mm/vmstat.c
index 74d66db..85928e0 100644
