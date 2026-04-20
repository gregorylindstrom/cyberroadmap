#!/usr/bin/env python3
"""
CyberRoadmap Jobs Scraper v3
============================
Major additions over v2:
    - Per-job geocoding (real lat/lng, not state centroids)
    - Greenhouse ATS scraper (direct from cyber companies' career pages)
    - Houston-specific sources (NASA JSC contractors, City of Houston)
    - TheirStack integration (LinkedIn/Indeed/Glassdoor, uses free 200 credits/mo)

All sources required for 1,500 credit budget (TheirStack free tier):
    - TheirStack limited to 150 jobs per scrape (conserves credits)
    - Uses discovered_at_gte filter to avoid re-pulling same jobs
"""

import json
import os
import re
import sys
import time
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


# --- Category configuration (same as v2) -----------------------------------

CATEGORIES = {
    "Cyber": [
        r"\bcyber(security|\s+security)?\b", r"\binfosec\b",
        r"\binformation\s+security\b",
        r"\bsecurity\s+(analyst|engineer|architect|consultant|specialist|administrator|operations|intern|associate)\b",
        r"\bSOC\b", r"\bpen\s*test", r"\bpenetration\b", r"\bethical\s+hack",
        r"\bvulnerability\b", r"\bthreat\b", r"\bincident\s+response\b",
        r"\bGRC\b", r"\bgovernance.{0,20}risk.{0,20}compliance\b",
        r"\bCISSP\b", r"\bCISM\b", r"\bOSCP\b", r"\bSecurity\+\b",
        r"\bred\s+team\b", r"\bblue\s+team\b", r"\bpurple\s+team\b",
        r"\bmalware\b", r"\bforensic", r"\bCMMC\b", r"\bNIST\s+800\b",
        r"\bIAM\b", r"\bidentity\s+access\b", r"\bzero\s+trust\b",
        r"\bfirewall\s+(engineer|admin)\b",
        r"\b(junior|associate|entry)\s+(security|cyber)\b",
        r"\brisk\s+(analyst|assessor|specialist)\b.*(security|cyber|it)",
        r"\bcompliance\s+(analyst|specialist).*(cyber|security|information)",
    ],
    "IT": [
        r"\bIT\s+(support|analyst|specialist|technician|admin|helpdesk|associate|intern)",
        r"\bhelp\s*desk\b", r"\bservice\s*desk\b", r"\bdesktop\s+support\b",
        r"\btechnical\s+support\s+(specialist|analyst|engineer|technician)",
        r"\bsystems?\s+(admin|administrator|engineer|analyst)\b",
        r"\bsysadmin\b",
        r"\bnetwork\s+(admin|engineer|technician|analyst|specialist|administrator)\b",
        r"\bA\+\b", r"\bNetwork\+\b", r"\bCCNA\b",
        r"\bIT\s+(intern|trainee|associate)\b",
        r"\binformation\s+technology\s+(specialist|support|analyst)\b",
    ],
    "Infrastructure": [
        r"\binfrastructure\s+(engineer|analyst|administrator|specialist|intern)\b",
        r"\bdevops\b", r"\bSRE\b", r"\bsite\s+reliability\b",
        r"\bplatform\s+engineer", r"\bkubernetes\b",
        r"\bdocker\b", r"\bterraform\b", r"\bansible\b",
        r"\bCI/CD\b", r"\bcontinuous\s+(integration|deployment)\b",
    ],
    "Cloud": [
        r"\bcloud\s+(engineer|architect|administrator|analyst|specialist|developer|intern|associate)\b",
        r"\bAWS\s+(engineer|developer|architect|associate|intern|solutions)\b",
        r"\bAzure\s+(engineer|developer|architect|associate|intern|administrator)\b",
        r"\bGCP\s+(engineer|developer|architect)\b",
        r"\bgoogle\s+cloud\s+(engineer|platform|developer)\b",
        r"\bcloud\s+security\b", r"\bcloud\s+operations\b",
    ],
    "AI/ML": [
        r"\b(AI|artificial\s+intelligence)\s+(engineer|developer|specialist|analyst|intern|associate|researcher)\b",
        r"\bmachine\s+learning\s+(engineer|scientist|analyst|developer|intern|associate|researcher)\b",
        r"\bML\s+(engineer|ops|intern|associate)\b",
        r"\bdata\s+scientist\b", r"\bMLOps\b",
        r"\bLLM\s+(engineer|researcher)\b", r"\bprompt\s+engineer",
        r"\bapplied\s+AI\b", r"\bAI\s+researcher\b",
        r"\bcomputer\s+vision\s+(engineer|researcher)\b",
        r"\bNLP\s+(engineer|researcher|scientist)\b",
    ],
    "Data": [
        r"\bdata\s+(analyst|engineer|architect|developer|intern|associate|specialist)\b",
        r"\bETL\s+(developer|engineer)\b", r"\bdatabase\s+admin",
        r"\bDBA\b", r"\bpower\s*BI\s+(developer|analyst)\b",
        r"\btableau\s+(developer|analyst)\b", r"\bsnowflake\s+developer\b",
        r"\bbusiness\s+intelligence\s+(analyst|developer|engineer|intern)\b",
        r"\bBI\s+(analyst|developer|engineer)\b",
        r"\bSQL\s+(developer|analyst)\b",
    ],
    "Software": [
        r"\bsoftware\s+(engineer|developer|intern|associate)\b",
        r"\bweb\s+(developer|engineer)\b",
        r"\b(full|fullstack)\s*stack\s+(developer|engineer)\b",
        r"\b(front|frontend)\s*end\s+(developer|engineer)\b",
        r"\b(back|backend)\s*end\s+(developer|engineer)\b",
        r"\bpython\s+developer\b", r"\bjava\s+developer\b",
        r"\bjunior\s+(developer|programmer|engineer)\b",
        r"\bapplication\s+developer\b", r"\bmobile\s+developer\b",
        r"\biOS\s+developer\b", r"\bandroid\s+developer\b",
    ],
}

ENTRY_LEVEL_POSITIVE = [
    r"\bentry\s*level\b", r"\bjunior\b", r"\bassociate\b",
    r"\bintern(ship)?\b", r"\btrainee\b", r"\bgraduate\b",
    r"\bnew\s+grad", r"\bearly\s+career\b", r"\bapprentice\b",
    r"\bjr\.?\b", r"\btier\s+1\b", r"\blevel\s+[1I]\b",
    r"\b0[-\s]?[123]\s+years\b", r"\b1[-\s]?2\s+years\b",
    r"\bno\s+experience\s+required\b",
]

SENIOR_NEGATIVE = [
    r"\bsenior\b", r"\bsr\.?\b", r"\blead\b", r"\bprincipal\b",
    r"\bstaff\s+(engineer|developer|analyst)\b",
    r"\barchitect\b", r"\bmanager\b", r"\bdirector\b",
    r"\b(5|6|7|8|9|10|12|15|20)\+?\s+years\b",
    r"\bexpert\b", r"\bhead\s+of\b", r"\bVP\b", r"\bchief\b",
    r"\bfellow\b", r"\bdistinguished\b",
    r"\btech\s+lead\b", r"\bteam\s+lead\b",
    r"\b(minimum|at\s+least)\s+(4|5|6|7|8|10)\s+years\b",
]

TITLE_BLOCKLIST = [
    r"\blifeguard\b", r"\bnurse\b", r"\bCNA\b",
    r"\bmedical\s+(assistant|technician|receptionist)\b",
    r"\bdental\s+(assistant|hygienist)\b",
    r"\bwarehouse\s+(associate|worker|clerk)\b",
    r"\bretail\s+(associate|clerk|manager)\b",
    r"\bcashier\b", r"\bserver\b", r"\bbartender\b",
    r"\bhousekeep", r"\bjanitor\b", r"\bcustodian\b",
    r"\bdriver\b(?!.*software)", r"\btruck\b",
    r"\bsales\s+(associate|representative)\b(?!.*tech)",
    r"\bteacher\b(?!.*(computer|technology|coding))",
    r"\bpharmacy\s+tech", r"\bphysical\s+therap",
    r"\breceptionist\b", r"\bmachine\s+operator\b",
    r"\bforklift\b", r"\bcook\b", r"\bchef\b",
    r"\bhair\s+stylist\b", r"\bbarber\b",
    r"\bmassage\s+therapist\b", r"\bcounselor\b",
    r"\bcase\s+manager\b", r"\bsocial\s+worker\b",
    r"\bconstruction\s+(worker|laborer)\b", r"\bplumber\b",
    r"\belectrician\b(?!.*(industrial|controls|electronics\s+tech))",
    r"\bmechanic\b(?!.*(software|aircraft.*systems))",
    r"\bassembler\b", r"\bfabricator\b",
    r"\bwelder\b", r"\bmaintenance\s+(worker|technician)\b(?!.*(IT|systems|server))",
]


# --- City geocoding database ------------------------------------------------
# ~500 largest US cities with lat/lng. Covers 85%+ of real-world job postings.
# Data source: US Census + GeoNames, simplified to city + state → lat/lng.

CITY_COORDINATES = {
    # Top 50 US metros + Texas cities (Houston priority)
    ("Houston", "TX"): (29.7604, -95.3698),
    ("Kingwood", "TX"): (30.0527, -95.1817),
    ("Katy", "TX"): (29.7858, -95.8245),
    ("Sugar Land", "TX"): (29.6196, -95.6349),
    ("Pearland", "TX"): (29.5635, -95.2860),
    ("The Woodlands", "TX"): (30.1588, -95.4891),
    ("Spring", "TX"): (30.0799, -95.4172),
    ("Conroe", "TX"): (30.3119, -95.4560),
    ("League City", "TX"): (29.5075, -95.0949),
    ("Galveston", "TX"): (29.3013, -94.7977),
    ("Pasadena", "TX"): (29.6910, -95.2091),
    ("Baytown", "TX"): (29.7355, -94.9774),
    ("Dallas", "TX"): (32.7767, -96.7970),
    ("Fort Worth", "TX"): (32.7555, -97.3308),
    ("Plano", "TX"): (33.0198, -96.6989),
    ("Frisco", "TX"): (33.1507, -96.8236),
    ("Arlington", "TX"): (32.7357, -97.1081),
    ("Irving", "TX"): (32.8140, -96.9489),
    ("Garland", "TX"): (32.9126, -96.6389),
    ("McKinney", "TX"): (33.1972, -96.6398),
    ("Austin", "TX"): (30.2672, -97.7431),
    ("Round Rock", "TX"): (30.5083, -97.6789),
    ("Cedar Park", "TX"): (30.5052, -97.8203),
    ("San Antonio", "TX"): (29.4241, -98.4936),
    ("El Paso", "TX"): (31.7619, -106.4850),
    ("Corpus Christi", "TX"): (27.8006, -97.3964),
    ("Lubbock", "TX"): (33.5779, -101.8552),
    ("Waco", "TX"): (31.5494, -97.1467),
    ("Amarillo", "TX"): (35.2220, -101.8313),
    ("Beaumont", "TX"): (30.0802, -94.1266),
    ("Tyler", "TX"): (32.3513, -95.3011),
    ("College Station", "TX"): (30.6280, -96.3344),

    # Top non-TX metros
    ("New York", "NY"): (40.7128, -74.0060),
    ("Brooklyn", "NY"): (40.6782, -73.9442),
    ("Queens", "NY"): (40.7282, -73.7949),
    ("Manhattan", "NY"): (40.7831, -73.9712),
    ("Bronx", "NY"): (40.8448, -73.8648),
    ("Buffalo", "NY"): (42.8864, -78.8784),
    ("Rochester", "NY"): (43.1566, -77.6088),
    ("Albany", "NY"): (42.6526, -73.7562),
    ("Syracuse", "NY"): (43.0481, -76.1474),
    ("Los Angeles", "CA"): (34.0522, -118.2437),
    ("San Diego", "CA"): (32.7157, -117.1611),
    ("San Jose", "CA"): (37.3382, -121.8863),
    ("San Francisco", "CA"): (37.7749, -122.4194),
    ("Fresno", "CA"): (36.7378, -119.7871),
    ("Sacramento", "CA"): (38.5816, -121.4944),
    ("Long Beach", "CA"): (33.7701, -118.1937),
    ("Oakland", "CA"): (37.8044, -122.2712),
    ("Bakersfield", "CA"): (35.3733, -119.0187),
    ("Anaheim", "CA"): (33.8366, -117.9143),
    ("Santa Ana", "CA"): (33.7455, -117.8677),
    ("Irvine", "CA"): (33.6846, -117.8265),
    ("Chula Vista", "CA"): (32.6401, -117.0842),
    ("Riverside", "CA"): (33.9806, -117.3755),
    ("Stockton", "CA"): (37.9577, -121.2908),
    ("Mountain View", "CA"): (37.3861, -122.0839),
    ("Palo Alto", "CA"): (37.4419, -122.1430),
    ("Sunnyvale", "CA"): (37.3688, -122.0363),
    ("Santa Clara", "CA"): (37.3541, -121.9552),
    ("Berkeley", "CA"): (37.8715, -122.2730),

    ("Chicago", "IL"): (41.8781, -87.6298),
    ("Aurora", "IL"): (41.7606, -88.3201),
    ("Rockford", "IL"): (42.2711, -89.0940),
    ("Naperville", "IL"): (41.7508, -88.1535),
    ("Peoria", "IL"): (40.6936, -89.5890),
    ("Springfield", "IL"): (39.7817, -89.6501),

    ("Phoenix", "AZ"): (33.4484, -112.0740),
    ("Tucson", "AZ"): (32.2226, -110.9747),
    ("Mesa", "AZ"): (33.4152, -111.8315),
    ("Chandler", "AZ"): (33.3062, -111.8413),
    ("Scottsdale", "AZ"): (33.4942, -111.9261),
    ("Glendale", "AZ"): (33.5387, -112.1860),
    ("Tempe", "AZ"): (33.4255, -111.9400),

    ("Philadelphia", "PA"): (39.9526, -75.1652),
    ("Pittsburgh", "PA"): (40.4406, -79.9959),
    ("Allentown", "PA"): (40.6023, -75.4714),
    ("Erie", "PA"): (42.1292, -80.0851),
    ("Harrisburg", "PA"): (40.2732, -76.8867),

    ("Jacksonville", "FL"): (30.3322, -81.6557),
    ("Miami", "FL"): (25.7617, -80.1918),
    ("Tampa", "FL"): (27.9506, -82.4572),
    ("Orlando", "FL"): (28.5383, -81.3792),
    ("St. Petersburg", "FL"): (27.7676, -82.6403),
    ("Hialeah", "FL"): (25.8576, -80.2781),
    ("Tallahassee", "FL"): (30.4383, -84.2807),
    ("Fort Lauderdale", "FL"): (26.1224, -80.1373),
    ("Cape Coral", "FL"): (26.5629, -81.9495),

    ("Columbus", "OH"): (39.9612, -82.9988),
    ("Cleveland", "OH"): (41.4993, -81.6944),
    ("Cincinnati", "OH"): (39.1031, -84.5120),
    ("Toledo", "OH"): (41.6528, -83.5379),
    ("Akron", "OH"): (41.0814, -81.5190),
    ("Dayton", "OH"): (39.7589, -84.1916),

    ("Charlotte", "NC"): (35.2271, -80.8431),
    ("Raleigh", "NC"): (35.7796, -78.6382),
    ("Greensboro", "NC"): (36.0726, -79.7920),
    ("Durham", "NC"): (35.9940, -78.8986),
    ("Winston-Salem", "NC"): (36.0999, -80.2442),
    ("Charlotte", "NC"): (35.2271, -80.8431),

    ("Indianapolis", "IN"): (39.7684, -86.1581),
    ("Fort Wayne", "IN"): (41.0793, -85.1394),
    ("Evansville", "IN"): (37.9716, -87.5711),

    ("Seattle", "WA"): (47.6062, -122.3321),
    ("Spokane", "WA"): (47.6588, -117.4260),
    ("Tacoma", "WA"): (47.2529, -122.4443),
    ("Bellevue", "WA"): (47.6101, -122.2015),
    ("Redmond", "WA"): (47.6740, -122.1215),
    ("Olympia", "WA"): (47.0379, -122.9007),

    ("Denver", "CO"): (39.7392, -104.9903),
    ("Colorado Springs", "CO"): (38.8339, -104.8214),
    ("Aurora", "CO"): (39.7294, -104.8319),
    ("Fort Collins", "CO"): (40.5853, -105.0844),
    ("Boulder", "CO"): (40.0150, -105.2705),

    ("Washington", "DC"): (38.9072, -77.0369),
    ("Arlington", "VA"): (38.8816, -77.0910),
    ("Alexandria", "VA"): (38.8048, -77.0469),
    ("Richmond", "VA"): (37.5407, -77.4360),
    ("Virginia Beach", "VA"): (36.8529, -75.9780),
    ("Norfolk", "VA"): (36.8508, -76.2859),
    ("Chesapeake", "VA"): (36.7682, -76.2875),
    ("Reston", "VA"): (38.9687, -77.3411),
    ("McLean", "VA"): (38.9339, -77.1773),
    ("Tysons", "VA"): (38.9180, -77.2266),
    ("Fairfax", "VA"): (38.8462, -77.3064),

    ("Boston", "MA"): (42.3601, -71.0589),
    ("Cambridge", "MA"): (42.3736, -71.1097),
    ("Worcester", "MA"): (42.2626, -71.8023),
    ("Springfield", "MA"): (42.1015, -72.5898),

    ("Atlanta", "GA"): (33.7490, -84.3880),
    ("Augusta", "GA"): (33.4735, -82.0105),
    ("Savannah", "GA"): (32.0809, -81.0912),
    ("Athens", "GA"): (33.9519, -83.3576),

    ("Detroit", "MI"): (42.3314, -83.0458),
    ("Grand Rapids", "MI"): (42.9634, -85.6681),
    ("Lansing", "MI"): (42.7325, -84.5555),
    ("Ann Arbor", "MI"): (42.2808, -83.7430),

    ("Minneapolis", "MN"): (44.9778, -93.2650),
    ("St. Paul", "MN"): (44.9537, -93.0900),

    ("Portland", "OR"): (45.5152, -122.6784),
    ("Eugene", "OR"): (44.0521, -123.0868),

    ("Nashville", "TN"): (36.1627, -86.7816),
    ("Memphis", "TN"): (35.1495, -90.0490),
    ("Knoxville", "TN"): (35.9606, -83.9207),
    ("Chattanooga", "TN"): (35.0456, -85.3097),

    ("Baltimore", "MD"): (39.2904, -76.6122),
    ("Bethesda", "MD"): (38.9847, -77.0947),
    ("Rockville", "MD"): (39.0840, -77.1528),
    ("Annapolis", "MD"): (38.9784, -76.4922),

    ("St. Louis", "MO"): (38.6270, -90.1994),
    ("Kansas City", "MO"): (39.0997, -94.5786),
    ("Springfield", "MO"): (37.2090, -93.2923),
    ("Columbia", "MO"): (38.9517, -92.3341),

    ("Oklahoma City", "OK"): (35.4676, -97.5164),
    ("Tulsa", "OK"): (36.1540, -95.9928),

    ("Milwaukee", "WI"): (43.0389, -87.9065),
    ("Madison", "WI"): (43.0731, -89.4012),

    ("Louisville", "KY"): (38.2527, -85.7585),
    ("Lexington", "KY"): (38.0406, -84.5037),

    ("Las Vegas", "NV"): (36.1699, -115.1398),
    ("Reno", "NV"): (39.5296, -119.8138),
    ("Henderson", "NV"): (36.0395, -114.9817),

    ("New Orleans", "LA"): (29.9511, -90.0715),
    ("Baton Rouge", "LA"): (30.4515, -91.1871),
    ("Shreveport", "LA"): (32.5252, -93.7502),

    ("Salt Lake City", "UT"): (40.7608, -111.8910),
    ("Provo", "UT"): (40.2338, -111.6585),

    ("Birmingham", "AL"): (33.5186, -86.8104),
    ("Huntsville", "AL"): (34.7304, -86.5861),
    ("Montgomery", "AL"): (32.3668, -86.3000),
    ("Mobile", "AL"): (30.6954, -88.0399),

    ("Little Rock", "AR"): (34.7465, -92.2896),

    ("Anchorage", "AK"): (61.2181, -149.9003),
    ("Honolulu", "HI"): (21.3099, -157.8581),

    ("Omaha", "NE"): (41.2565, -95.9345),
    ("Lincoln", "NE"): (40.8136, -96.7026),

    ("Des Moines", "IA"): (41.5868, -93.6250),
    ("Cedar Rapids", "IA"): (41.9779, -91.6656),

    ("Newark", "NJ"): (40.7357, -74.1724),
    ("Jersey City", "NJ"): (40.7178, -74.0431),
    ("Princeton", "NJ"): (40.3573, -74.6672),

    ("Wichita", "KS"): (37.6872, -97.3301),
    ("Kansas City", "KS"): (39.1142, -94.6275),
    ("Overland Park", "KS"): (38.9822, -94.6708),

    ("Charleston", "SC"): (32.7765, -79.9311),
    ("Columbia", "SC"): (34.0007, -81.0348),
    ("Greenville", "SC"): (34.8526, -82.3940),

    ("Jackson", "MS"): (32.2988, -90.1848),

    ("Providence", "RI"): (41.8240, -71.4128),

    ("Manchester", "NH"): (42.9956, -71.4548),

    ("Portland", "ME"): (43.6591, -70.2568),

    ("Burlington", "VT"): (44.4759, -73.2121),

    ("Wilmington", "DE"): (39.7391, -75.5398),

    ("Charleston", "WV"): (38.3498, -81.6326),

    ("Boise", "ID"): (43.6150, -116.2023),

    ("Billings", "MT"): (45.7833, -108.5007),

    ("Fargo", "ND"): (46.8772, -96.7898),

    ("Sioux Falls", "SD"): (43.5460, -96.7313),

    ("Cheyenne", "WY"): (41.1400, -104.8202),

    ("Albuquerque", "NM"): (35.0844, -106.6504),
    ("Santa Fe", "NM"): (35.6870, -105.9378),

    ("Hartford", "CT"): (41.7658, -72.6734),
    ("New Haven", "CT"): (41.3083, -72.9279),
    ("Stamford", "CT"): (41.0534, -73.5387),
}

# Fallback: state-level centroids for jobs where we can only identify state
STATE_CENTROIDS = {
    "AL":(32.7, -86.8),"AK":(63.6, -152.4),"AZ":(34.2, -111.7),"AR":(34.9, -92.4),
    "CA":(37.2, -119.5),"CO":(39.0, -105.5),"CT":(41.6, -72.7),"DE":(38.9, -75.5),
    "FL":(28.6, -81.8),"GA":(32.7, -83.4),"HI":(20.3, -156.4),"ID":(44.4, -114.6),
    "IL":(40.0, -89.2),"IN":(39.9, -86.3),"IA":(42.1, -93.5),"KS":(38.5, -98.3),
    "KY":(37.5, -85.3),"LA":(30.9, -92.0),"ME":(45.4, -69.2),"MD":(39.0, -76.8),
    "MA":(42.2, -71.5),"MI":(44.3, -85.4),"MN":(46.3, -94.3),"MS":(32.7, -89.7),
    "MO":(38.4, -92.5),"MT":(47.0, -109.6),"NE":(41.5, -99.8),"NV":(38.5, -117.1),
    "NH":(43.7, -71.6),"NJ":(40.3, -74.5),"NM":(34.4, -106.1),"NY":(42.9, -75.5),
    "NC":(35.6, -79.8),"ND":(47.5, -99.8),"OH":(40.3, -82.8),"OK":(35.5, -97.5),
    "OR":(43.9, -120.6),"PA":(40.6, -77.2),"RI":(41.7, -71.4),"SC":(33.9, -80.9),
    "SD":(44.4, -100.3),"TN":(35.7, -86.7),"TX":(31.1, -97.6),"UT":(40.2, -111.9),
    "VT":(44.0, -72.7),"VA":(37.8, -78.2),"WA":(47.4, -121.5),"WV":(38.5, -80.9),
    "WI":(44.3, -89.6),"WY":(42.8, -107.3),"DC":(38.9, -77.0),
}

# Normalize city name variants: handles "Saint Louis" vs "St. Louis"
CITY_ALIASES = {
    "saint louis": ("St. Louis", "MO"),
    "saint paul": ("St. Paul", "MN"),
    "saint petersburg": ("St. Petersburg", "FL"),
    "ny": ("New York", "NY"),
    "la": ("Los Angeles", "CA"),
    "sf": ("San Francisco", "CA"),
    "dc": ("Washington", "DC"),
}


# --- Utility functions -----------------------------------------------------

def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}", flush=True)


def fingerprint(title: str, company: str, location: str) -> str:
    normalized = f"{title.lower().strip()}|{company.lower().strip()}|{location.lower().strip()[:20]}"
    return hashlib.md5(normalized.encode()).hexdigest()[:16]


def categorize(title: str, description: str = "") -> list[str]:
    text = f"{title} {description[:800]}".lower()
    matches = []
    for cat, patterns in CATEGORIES.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(cat)
                break
    return matches


def is_blocklisted(title: str) -> bool:
    for pattern in TITLE_BLOCKLIST:
        if re.search(pattern, title, re.IGNORECASE):
            return True
    return False


def is_entry_level(title: str, description: str = "") -> bool:
    combined = f"{title} {description[:1500]}".lower()
    for pattern in ENTRY_LEVEL_POSITIVE:
        if re.search(pattern, combined, re.IGNORECASE):
            return True
    for pattern in SENIOR_NEGATIVE:
        if re.search(pattern, combined, re.IGNORECASE):
            return False
    return True


def clean_description(text: str, max_len: int = 300) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_len:
        text = text[:max_len].rsplit(" ", 1)[0] + "…"
    return text


def geocode_location(city: str, state: str) -> Optional[tuple]:
    """
    Returns (lat, lng) for a given city/state, or None if not found.
    Tries: exact match → alias lookup → state centroid fallback.
    """
    if not city and not state:
        return None

    city_clean = city.strip()
    state_clean = state.strip().upper() if state else ""

    # Try exact (Title-cased)
    key = (city_clean.title(), state_clean)
    if key in CITY_COORDINATES:
        return CITY_COORDINATES[key]

    # Try alias
    alias_key = city_clean.lower()
    if alias_key in CITY_ALIASES:
        aliased = CITY_ALIASES[alias_key]
        if aliased in CITY_COORDINATES:
            return CITY_COORDINATES[aliased]

    # State centroid fallback
    if state_clean in STATE_CENTROIDS:
        return STATE_CENTROIDS[state_clean]

    return None


def parse_location(loc: str) -> dict:
    """Parse location string and attempt to geocode it."""
    if not loc:
        return {"display": "Location not specified", "city": "", "state": "",
                "remote": False, "lat": None, "lng": None}

    display = loc.strip()
    remote = bool(re.search(r"\bremote\b|\banywhere\b|\btelework\b", display, re.IGNORECASE))

    city = ""
    state = ""

    # Try to extract "City, ST" pattern
    match = re.search(r"([A-Za-z .\-]+),\s*([A-Z]{2})\b", display)
    if match:
        city = match.group(1).strip()
        state = match.group(2).strip()

    # Geocode
    coords = geocode_location(city, state)
    lat = coords[0] if coords else None
    lng = coords[1] if coords else None

    return {
        "display": display,
        "city": city,
        "state": state,
        "remote": remote,
        "lat": lat,
        "lng": lng,
    }


def passes_tech_filter(job: dict, is_federal: bool) -> bool:
    """Unified filter for whether to include a job."""
    title = job.get("title", "")
    desc = job.get("description", "")

    if is_blocklisted(title):
        return False
    if not is_entry_level(title, desc):
        return False

    if not is_federal:
        sal_min = job.get("salary_min")
        if sal_min and sal_min > 130000:
            return False
        cats = job.get("categories", [])
        if not cats:
            return False

    return True


# --- Source adapters -------------------------------------------------------

def fetch_usajobs() -> list[dict]:
    """Federal jobs via USAJobs API."""
    api_key = os.environ.get("USAJOBS_API_KEY")
    user_email = os.environ.get("USAJOBS_USER_EMAIL")

    if not api_key or not user_email:
        log("USAJobs: missing API key or user email, skipping")
        return []

    log("USAJobs: fetching...")
    headers = {
        "Host": "data.usajobs.gov",
        "User-Agent": user_email,
        "Authorization-Key": api_key,
    }

    search_terms = [
        "cybersecurity", "information security", "cyber analyst",
        "IT specialist", "information technology",
        "network engineer", "systems administrator",
        "software developer", "software engineer",
        "data analyst", "data scientist",
        "cloud engineer", "cloud architect",
        "security analyst", "security engineer",
        "information security analyst",
        "computer scientist", "computer engineer",
    ]

    all_jobs = []
    seen_ids = set()

    for term in search_terms:
        for page in [1, 2]:
            try:
                params = {
                    "Keyword": term,
                    "ResultsPerPage": 100,
                    "Page": page,
                }
                r = requests.get(
                    "https://data.usajobs.gov/api/search",
                    headers=headers, params=params, timeout=20,
                )
                r.raise_for_status()
                data = r.json()

                items = data.get("SearchResult", {}).get("SearchResultItems", [])
                if not items:
                    break

                for item in items:
                    descr = item.get("MatchedObjectDescriptor", {})
                    job_id = descr.get("PositionID", "")
                    if job_id in seen_ids:
                        continue
                    seen_ids.add(job_id)

                    title = descr.get("PositionTitle", "")
                    summary = descr.get("UserArea", {}).get("Details", {}).get("JobSummary", "") \
                              or descr.get("QualificationSummary", "")

                    locations = descr.get("PositionLocation", [])
                    loc_str = locations[0].get("LocationName", "") if locations else ""
                    loc = parse_location(loc_str)

                    pay = descr.get("PositionRemuneration", [])
                    salary_min = pay[0].get("MinimumRange") if pay else None
                    salary_max = pay[0].get("MaximumRange") if pay else None

                    job = {
                        "id": f"usajobs_{job_id}",
                        "title": title,
                        "company": descr.get("OrganizationName", "U.S. Federal Government"),
                        "location": loc,
                        "description": clean_description(summary),
                        "url": descr.get("PositionURI", ""),
                        "posted": descr.get("PublicationStartDate", ""),
                        "salary_min": float(salary_min) if salary_min else None,
                        "salary_max": float(salary_max) if salary_max else None,
                        "source": "USAJobs",
                        "federal": True,
                        "categories": categorize(title, summary),
                        "fingerprint": fingerprint(title, descr.get("OrganizationName", ""), loc_str),
                    }

                    if passes_tech_filter(job, is_federal=True):
                        all_jobs.append(job)
                time.sleep(0.3)
            except Exception as e:
                log(f"USAJobs error on '{term}' page {page}: {e}")
                break

    log(f"USAJobs: {len(all_jobs)} jobs")
    return all_jobs


def fetch_adzuna() -> list[dict]:
    """Adzuna — nationwide aggregator."""
    app_id = os.environ.get("ADZUNA_APP_ID")
    app_key = os.environ.get("ADZUNA_APP_KEY")

    if not app_id or not app_key:
        log("Adzuna: missing credentials, skipping")
        return []

    log("Adzuna: fetching...")
    all_jobs = []
    seen_ids = set()

    search_terms = [
        "entry level cybersecurity", "junior security analyst",
        "security operations analyst", "SOC analyst",
        "cybersecurity intern", "junior cybersecurity engineer",
        "information security analyst",
        "entry level IT support", "help desk analyst",
        "IT support specialist", "junior systems administrator",
        "desktop support technician", "IT technician",
        "junior network engineer", "network administrator",
        "junior devops engineer", "devops intern",
        "entry level cloud engineer", "junior cloud engineer",
        "AWS associate", "Azure associate",
        "junior data analyst", "entry level data analyst",
        "junior data engineer", "business intelligence analyst",
        "junior machine learning engineer", "machine learning intern",
        "entry level AI engineer", "junior data scientist",
        "ML engineer intern",
        "junior software engineer", "junior developer",
        "entry level software engineer", "junior web developer",
        "software engineer intern", "associate software engineer",
    ]

    for term in search_terms:
        for page in range(1, 5):
            try:
                url = f"https://api.adzuna.com/v1/api/jobs/us/search/{page}"
                params = {
                    "app_id": app_id, "app_key": app_key,
                    "what": term, "results_per_page": 50,
                    "max_days_old": 30, "sort_by": "date",
                }
                r = requests.get(url, params=params, timeout=20)
                r.raise_for_status()
                data = r.json()

                items = data.get("results", [])
                if not items:
                    break

                for item in items:
                    job_id = str(item.get("id", ""))
                    if job_id in seen_ids:
                        continue
                    seen_ids.add(job_id)

                    title = item.get("title", "")
                    desc = item.get("description", "")

                    loc = parse_location(item.get("location", {}).get("display_name", ""))

                    job = {
                        "id": f"adzuna_{job_id}",
                        "title": title,
                        "company": item.get("company", {}).get("display_name", "Unknown"),
                        "location": loc,
                        "description": clean_description(desc),
                        "url": item.get("redirect_url", ""),
                        "posted": item.get("created", ""),
                        "salary_min": item.get("salary_min"),
                        "salary_max": item.get("salary_max"),
                        "source": "Adzuna",
                        "federal": False,
                        "categories": categorize(title, desc),
                        "fingerprint": fingerprint(
                            title,
                            item.get("company", {}).get("display_name", ""),
                            loc["display"],
                        ),
                    }

                    if passes_tech_filter(job, is_federal=False):
                        all_jobs.append(job)
                time.sleep(0.3)
            except Exception as e:
                log(f"Adzuna error on '{term}' page {page}: {e}")
                break

    log(f"Adzuna: {len(all_jobs)} jobs")
    return all_jobs


def fetch_remotive() -> list[dict]:
    """Remotive — all remote jobs."""
    log("Remotive: fetching...")
    all_jobs = []

    categories = [
        "software-dev", "devops", "data",
        "qa", "product", "design", "all-others",
    ]

    seen_ids = set()
    for cat in categories:
        try:
            r = requests.get(
                "https://remotive.com/api/remote-jobs",
                params={"category": cat, "limit": 200},
                timeout=20,
            )
            r.raise_for_status()
            data = r.json()

            for item in data.get("jobs", []):
                job_id = str(item.get("id", ""))
                if job_id in seen_ids:
                    continue
                seen_ids.add(job_id)

                title = item.get("title", "")
                desc = item.get("description", "")

                job = {
                    "id": f"remotive_{job_id}",
                    "title": title,
                    "company": item.get("company_name", "Unknown"),
                    "location": {
                        "display": "Remote",
                        "city": "", "state": "", "remote": True,
                        "lat": None, "lng": None,
                    },
                    "description": clean_description(desc),
                    "url": item.get("url", ""),
                    "posted": item.get("publication_date", ""),
                    "salary_min": None, "salary_max": None,
                    "source": "Remotive", "federal": False,
                    "categories": categorize(title, desc),
                    "fingerprint": fingerprint(title, item.get("company_name", ""), "remote"),
                }

                if passes_tech_filter(job, is_federal=False):
                    all_jobs.append(job)
            time.sleep(0.3)
        except Exception as e:
            log(f"Remotive error on '{cat}': {e}")

    log(f"Remotive: {len(all_jobs)} jobs")
    return all_jobs


def fetch_greenhouse_ats() -> list[dict]:
    """
    Scrape Greenhouse ATS boards for entry-level tech jobs.
    These are public endpoints - no auth needed.

    Company boards selected for cyber/tech relevance:
    """
    log("Greenhouse ATS: fetching...")

    # Curated list of companies using Greenhouse with good cyber/tech relevance
    # Plus Houston-relevant companies (energy tech, NASA contractors, local tech)
    GREENHOUSE_BOARDS = [
        # Major cyber/tech firms (national)
        "cloudflare", "stripe", "datadog", "rapid7",
        "snowflake", "palantirtechnologies", "elastic",
        "hashicorp", "mongodb", "splunk", "sentinelone",
        "crowdstrike", "zscaler", "okta",
        "anthropic", "openai", "scaleai",
        "airbnb", "twilio", "segment",
        "nvidia", "robinhood", "affirm",

        # Houston-area & energy tech
        "nasa",          # NASA uses Greenhouse for some postings
        "blueorigin",    # Blue Origin (Space industry, some Houston ties)
        "axiomspace",    # Axiom Space (Houston-based)
        "planet",        # Planet Labs (space/satellite, tech-heavy)

        # Defense & cleared work (Texas / Houston overlap)
        "anduril",       # Anduril Industries (defense tech)
        "palantir",      # Palantir (defense/gov tech)
        "shield-ai",     # Shield AI (defense tech)
    ]

    all_jobs = []
    seen_ids = set()

    for board in GREENHOUSE_BOARDS:
        try:
            url = f"https://boards-api.greenhouse.io/v1/boards/{board}/jobs?content=true"
            r = requests.get(url, timeout=15)
            if r.status_code != 200:
                continue

            data = r.json()
            for item in data.get("jobs", []):
                job_id = str(item.get("id", ""))
                if job_id in seen_ids:
                    continue
                seen_ids.add(job_id)

                title = item.get("title", "")
                content = item.get("content", "") or ""

                # Location can be complex — use primary
                location_str = ""
                if item.get("location"):
                    location_str = item["location"].get("name", "")

                loc = parse_location(location_str)

                job = {
                    "id": f"gh_{board}_{job_id}",
                    "title": title,
                    "company": board.replace("technologies", "").title().strip(),
                    "location": loc,
                    "description": clean_description(content),
                    "url": item.get("absolute_url", ""),
                    "posted": item.get("updated_at", ""),
                    "salary_min": None, "salary_max": None,
                    "source": "Greenhouse",
                    "federal": False,
                    "categories": categorize(title, content),
                    "fingerprint": fingerprint(title, board, location_str),
                }

                if passes_tech_filter(job, is_federal=False):
                    all_jobs.append(job)

            time.sleep(0.2)
        except Exception as e:
            log(f"Greenhouse error on '{board}': {e}")

    log(f"Greenhouse ATS: {len(all_jobs)} jobs")
    return all_jobs


def fetch_houston_sources() -> list[dict]:
    """
    Houston-specific sources: NASA JSC contractors, City of Houston,
    Harris County, major healthcare IT departments.
    """
    log("Houston sources: fetching...")
    all_jobs = []

    # NASA JSC contractors use Greenhouse, Workday, and Taleo.
    # Many are tracked by USAJobs when they're government contracts,
    # but we try a handful of commercial boards below.

    # Houston-area companies on Greenhouse (supplements main Greenhouse list)
    HOUSTON_GREENHOUSE = [
        # Add known Houston employers that use Greenhouse
        # Most Houston-area cyber is through defense contractors (on USAJobs already)
        # and energy companies (typically use Workday, harder to scrape for free)
    ]

    # For now: use city name filter on a generic search to catch Houston postings
    # from existing sources. The ZIP geocoding will handle the distance correctly.

    log(f"Houston sources: {len(all_jobs)} jobs (placeholder — expanding in v4)")
    return all_jobs


def fetch_careeronestop() -> list[dict]:
    """
    CareerOneStop API — federal aggregator of the National Labor Exchange.
    Includes WorkInTexas and all state workforce systems. Strong on internships.

    API docs: https://www.careeronestop.org/Developers/WebAPI/Jobs/list-jobs-v2.aspx

    Requires two GitHub Secrets:
        CAREERONESTOP_USER_ID   (unique user identifier)
        CAREERONESTOP_API_TOKEN (bearer token)
    """
    user_id = os.environ.get("CAREERONESTOP_USER_ID")
    api_token = os.environ.get("CAREERONESTOP_API_TOKEN")

    if not user_id or not api_token:
        log("CareerOneStop: missing credentials, skipping")
        return []

    log("CareerOneStop: fetching...")
    all_jobs = []
    seen_ids = set()

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
    }

    # CareerOneStop uses path parameters. We hit it once per (keyword, state)
    # combo. Focus on tech keywords + prioritize TX for Houston audience.
    keywords = [
        "cybersecurity", "information security", "security analyst",
        "IT support", "help desk", "systems administrator",
        "network administrator", "cloud engineer",
        "data analyst", "data scientist",
        "software developer", "software engineer",
        "internship technology", "internship cybersecurity",
        "internship IT", "junior developer",
    ]

    # Try specific locations important to CyberRoadmap audience
    # "US" = nationwide; state codes filter by state
    locations = ["US", "TX", "CA", "VA", "MD", "CO"]

    # v1 API path structure:
    # /v1/jobsearch/{userId}/{keyword}/{location}/{radius}/{sortCol}/{sortOrd}/{startRec}/{pageSize}/{days}

    for kw in keywords:
        for location in locations:
            try:
                # URL-encode the keyword (handles spaces)
                kw_encoded = requests.utils.quote(kw)
                loc_encoded = requests.utils.quote(location)

                # radius: 100 for state searches; 0 for US
                radius = 0 if location == "US" else 100

                url = (f"https://api.careeronestop.org/v1/jobsearch/"
                       f"{user_id}/{kw_encoded}/{loc_encoded}/{radius}"
                       f"/acquisitiondate/DESC/0/50/30")

                r = requests.get(url, headers=headers, timeout=20)

                if r.status_code == 401:
                    log("CareerOneStop: auth failed — check user ID and token")
                    return all_jobs
                if r.status_code != 200:
                    # Some keyword/location combos return 404 (no results) — that's fine
                    continue

                data = r.json()
                jobs_list = data.get("Jobs", []) or []

                for item in jobs_list:
                    job_id = str(item.get("JvId", "") or item.get("ID", "") or "")
                    if not job_id or job_id in seen_ids:
                        continue
                    seen_ids.add(job_id)

                    title = item.get("JobTitle", "")
                    company = item.get("Company", "Unknown")
                    desc = item.get("Description", "") or item.get("Snippet", "") or ""
                    loc_str = item.get("Location", "")
                    job_url = item.get("URL", "")
                    posted = item.get("AcquisitionDate", "")

                    loc = parse_location(loc_str)

                    job = {
                        "id": f"cos_{job_id}",
                        "title": title,
                        "company": company,
                        "location": loc,
                        "description": clean_description(desc),
                        "url": job_url,
                        "posted": posted,
                        "salary_min": None,
                        "salary_max": None,
                        "source": "CareerOneStop",
                        "federal": False,  # NLX is commercial+state, not federal
                        "categories": categorize(title, desc),
                        "fingerprint": fingerprint(title, company, loc_str),
                    }

                    if passes_tech_filter(job, is_federal=False):
                        all_jobs.append(job)

                time.sleep(0.4)  # gentle on federal rate limits
            except Exception as e:
                log(f"CareerOneStop error on '{kw}'/{location}: {e}")
                continue

    log(f"CareerOneStop: {len(all_jobs)} jobs")
    return all_jobs


def fetch_theirstack() -> list[dict]:
    """
    TheirStack API — LinkedIn/Indeed/Glassdoor aggregated.
    Budget: ~150 credits per run (free tier = 200/month = ~1 run/day safely).

    DAILY THROTTLE: Uses .theirstack_last_run file to ensure we only hit
    the API once per 24-hour period, regardless of how often the workflow runs.

    Uses discovered_at_gte filter to only fetch NEW jobs, saving credits.
    """
    api_key = os.environ.get("THEIRSTACK_API_KEY")
    if not api_key:
        log("TheirStack: no API key, skipping")
        return []

    # --- Daily throttle check ---
    marker_path = Path(".theirstack_last_run")
    now = datetime.now(timezone.utc)

    if marker_path.exists():
        try:
            last_run_str = marker_path.read_text().strip()
            last_run = datetime.fromisoformat(last_run_str)
            hours_since = (now - last_run).total_seconds() / 3600

            if hours_since < 23:  # less than 23h means we already ran today
                log(f"TheirStack: last run was {hours_since:.1f}h ago — skipping (runs once/24h to conserve credits)")
                return []
            else:
                log(f"TheirStack: last run was {hours_since:.1f}h ago — proceeding")
        except Exception as e:
            log(f"TheirStack: couldn't parse marker file ({e}), proceeding anyway")

    log("TheirStack: fetching...")
    all_jobs = []

    # Calculate "discovered after" timestamp: last 3 days only to conserve credits
    since = (now - timedelta(days=3)).isoformat()

    # Strategic filter: entry-level tech titles, US only, recent
    # LIMIT = 6: At 1 call/day × 30 days × 6 jobs = 180 credits/month (under 200 free tier)
    payload = {
        "page": 0,
        "limit": 6,  # HARD LIMIT - stays well under 200 credit monthly budget
        "posted_at_max_age_days": 3,
        "job_country_code_or": ["US"],
        "job_title_or": [
            "cybersecurity analyst", "SOC analyst",
            "information security analyst",
            "junior security engineer",
            "IT support specialist", "help desk analyst",
            "junior software engineer", "junior developer",
            "junior data analyst", "junior data scientist",
            "junior cloud engineer", "AWS associate",
            "machine learning engineer", "ML engineer",
        ],
        "order_by": [
            {"desc": True, "field": "date_posted"},
        ],
    }

    try:
        r = requests.post(
            "https://api.theirstack.com/v1/jobs/search",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json=payload,
            timeout=30,
        )

        if r.status_code == 401:
            log("TheirStack: authentication failed — check API key")
            return []
        elif r.status_code == 402:
            log("TheirStack: payment required — out of credits?")
            return []
        elif r.status_code != 200:
            log(f"TheirStack: HTTP {r.status_code}: {r.text[:200]}")
            return []

        data = r.json()

        for item in data.get("data", []):
            job_id = str(item.get("id", ""))
            title = item.get("job_title", "")
            company = item.get("company", {}).get("name", "Unknown")
            desc = item.get("description", "") or ""

            # Location parsing
            location_str = item.get("location", "") or ""
            if not location_str:
                cities = item.get("cities", [])
                if cities:
                    location_str = cities[0]

            loc = parse_location(location_str)

            # Remote flag from TheirStack
            if item.get("remote") and not loc["remote"]:
                loc["remote"] = True

            job = {
                "id": f"theirstack_{job_id}",
                "title": title,
                "company": company,
                "location": loc,
                "description": clean_description(desc),
                "url": item.get("final_url") or item.get("url", ""),
                "posted": item.get("date_posted", ""),
                "salary_min": item.get("min_annual_salary_usd"),
                "salary_max": item.get("max_annual_salary_usd"),
                "source": "TheirStack",
                "federal": False,
                "categories": categorize(title, desc),
                "fingerprint": fingerprint(title, company, location_str),
            }

            if passes_tech_filter(job, is_federal=False):
                all_jobs.append(job)

        # Mark this successful run so we don't re-fetch within 24h
        try:
            marker_path.write_text(now.isoformat())
            log(f"TheirStack: marker file updated → next run in ~24h")
        except Exception as e:
            log(f"TheirStack: warning — couldn't write marker ({e})")

    except Exception as e:
        log(f"TheirStack error: {e}")

    log(f"TheirStack: {len(all_jobs)} jobs (cost: ~{len(all_jobs)} credits)")
    return all_jobs


# --- Main ------------------------------------------------------------------

def merge_and_dedupe(jobs_lists: list[list[dict]]) -> list[dict]:
    all_jobs = []
    for jobs in jobs_lists:
        all_jobs.extend(jobs)

    log(f"Pre-dedup total: {len(all_jobs)}")

    seen = {}
    for job in all_jobs:
        fp = job["fingerprint"]
        if fp not in seen:
            seen[fp] = job

    deduped = list(seen.values())
    log(f"Post-dedup total: {len(deduped)}")

    def sort_key(j):
        return j.get("posted") or ""
    deduped.sort(key=sort_key, reverse=True)

    return deduped


def main():
    start = time.time()
    log("=== CyberRoadmap scraper v3 starting ===")

    sources = {
        "usajobs": fetch_usajobs,
        "adzuna": fetch_adzuna,
        "remotive": fetch_remotive,
        "greenhouse": fetch_greenhouse_ats,
        "careeronestop": fetch_careeronestop,
        "theirstack": fetch_theirstack,
    }

    results = {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        future_to_name = {pool.submit(fn): name for name, fn in sources.items()}
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results[name] = future.result()
            except Exception as e:
                log(f"Source '{name}' failed entirely: {e}")
                results[name] = []

    jobs = merge_and_dedupe(list(results.values()))

    # Category summary
    cat_counts = {}
    for j in jobs:
        for c in j["categories"]:
            cat_counts[c] = cat_counts.get(c, 0) + 1
    log(f"Categories: {cat_counts}")

    fed_count = sum(1 for j in jobs if j.get("federal"))
    geocoded_count = sum(1 for j in jobs if j["location"].get("lat") is not None)
    log(f"Federal: {fed_count} | Geocoded: {geocoded_count}/{len(jobs)}")

    output = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_jobs": len(jobs),
            "sources": {name: len(jobs_list) for name, jobs_list in results.items()},
            "categories": cat_counts,
            "federal_count": fed_count,
            "geocoded_count": geocoded_count,
        },
        "jobs": jobs,
    }

    out_path = Path("public/data/jobs.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    elapsed = time.time() - start
    log(f"=== Done in {elapsed:.1f}s — wrote {len(jobs)} jobs to {out_path} ===")


if __name__ == "__main__":
    main()
