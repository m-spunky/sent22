"""
Campaign Clustering module using Agglomerative Clustering (Enhancement 5).

Groups distinct phishing events into inferred, zero-day campaigns based on:
- Sender domain/IP
- Timestamp proximity (time)
- Structural similarity (e.g., HTML structure, extracted features)
- IOC overlap (shared domains, links)
"""

import numpy as np
from sklearn.cluster import AgglomerativeClustering
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from datetime import datetime
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def compute_time_distance(t1_str: str, t2_str: str) -> float:
    """Compute distance based on time difference (hours). Max distance is 1.0 (>= 48h)."""
    try:
        t1 = datetime.fromisoformat(t1_str.replace("Z", "+00:00"))
        t2 = datetime.fromisoformat(t2_str.replace("Z", "+00:00"))
        diff_hours = abs((t1 - t2).total_seconds()) / 3600.0
        return min(diff_hours / 48.0, 1.0)
    except Exception:
        return 1.0


def compute_sender_distance(s1: str, s2: str) -> float:
    """0 if identical sender, 1 if different."""
    if not s1 or not s2:
        return 1.0
    return 0.0 if s1.lower() == s2.lower() else 1.0


def compute_ioc_distance(iocs1: List[str], iocs2: List[str]) -> float:
    """Jaccard distance for IOCs. 0 if identical, 1 if disjoint."""
    set1, set2 = set(iocs1), set(iocs2)
    if not set1 and not set2:
        return 0.5  # Neutral if both have no IOCs
    if not set1 or not set2:
        return 1.0
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    return 1.0 - (intersection / union)


def cluster_events(events: List[Dict[str, Any]], distance_threshold: float = 1.5) -> List[Dict[str, Any]]:
    """
    Cluster a list of analysis events into inferred campaigns.
    
    events: List of dicts, expected to have:
      - id / event_id
      - timestamp / analyzed_at
      - sender_domain (optional)
      - text / content / subject (for structural similarity)
      - iocs (list of strings, optional)
    """
    if not events:
        return []
    
    n = len(events)
    if n == 1:
        # Single event is its own cluster
        return [{"cluster_id": "Cluster-0", "size": 1, "events": events, "common_traits": []}]

    # 1. Structural similarity using TF-IDF on content/subject
    texts = [e.get("text") or e.get("content") or e.get("subject") or e.get("input") or "" for e in events]
    vectorizer = TfidfVectorizer(stop_words="english", max_features=100)
    try:
        tfidf_matrix = vectorizer.fit_transform(texts)
        structural_sim = cosine_similarity(tfidf_matrix)
    except Exception as e:
        logger.warning(f"TF-IDF failed: {e}")
        structural_sim = np.eye(n)
        
    structural_dist = 1.0 - structural_sim

    # 2. Build combined distance matrix
    # Weights: Structure 0.35, Time 0.25, Sender 0.20, IOC 0.20
    dist_matrix = np.zeros((n, n))
    
    for i in range(n):
        for j in range(i, n):
            if i == j:
                dist_matrix[i][j] = 0.0
                continue
                
            e1, e2 = events[i], events[j]
            
            # Time distance
            t1 = e1.get("timestamp") or e1.get("analyzed_at", "")
            t2 = e2.get("timestamp") or e2.get("analyzed_at", "")
            d_time = compute_time_distance(t1, t2)
            
            # Sender distance
            s1 = e1.get("sender_domain", "")
            s2 = e2.get("sender_domain", "")
            d_sender = compute_sender_distance(s1, s2)
            
            # IOC distance
            iocs1 = e1.get("iocs", [])
            iocs2 = e2.get("iocs", [])
            d_ioc = compute_ioc_distance(iocs1, iocs2)
            
            # Combine
            d_struct = structural_dist[i][j]
            
            # Weighted distance
            dist = (0.35 * d_struct) + (0.25 * d_time) + (0.20 * d_sender) + (0.20 * d_ioc)
            
            dist_matrix[i][j] = dist
            dist_matrix[j][i] = dist

    # 3. Perform Agglomerative Clustering
    clustering = AgglomerativeClustering(
        n_clusters=None,
        distance_threshold=distance_threshold,
        metric="precomputed",
        linkage="average"
    )
    labels = clustering.fit_predict(dist_matrix)

    # 4. Group results
    clusters_map = {}
    for i, label in enumerate(labels):
        cluster_id = f"Campaign-Inferred-{label}"
        if cluster_id not in clusters_map:
            clusters_map[cluster_id] = {"cluster_id": cluster_id, "size": 0, "events": [], "common_traits": []}
        
        clusters_map[cluster_id]["events"].append(events[i])
        clusters_map[cluster_id]["size"] += 1

    # 5. Extract common traits for each cluster
    for c_id, c_data in clusters_map.items():
        if c_data["size"] > 1:
            traits = []
            evs = c_data["events"]
            
            # Check common sender
            senders = set(e.get("sender_domain") for e in evs if e.get("sender_domain"))
            if len(senders) == 1:
                traits.append(f"Shared sender domain: {list(senders)[0]}")
                
            # Check intersecting IOCs
            active_iocs = [set(e.get("iocs", [])) for e in evs if e.get("iocs")]
            if len(active_iocs) > 1:
                intersection = set.intersection(*active_iocs)
                if intersection:
                    traits.append(f"Shared IOCs: {', '.join(list(intersection)[:3])}")
            
            c_data["common_traits"] = traits

    return list(clusters_map.values())
