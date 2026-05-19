# 10. Compass Security OSINT Cheat Sheet Reference

Full content from the Compass Security OSINT Cheat Sheet (2017-01).

## 10.1 Google Hacking

**Google Hacking Database (GHDB):** https://www.exploit-db.com/google-hacking-database/
Authoritative source for search terms that surface usernames, passwords, and sensitive files indexed by Google.

**Google and Bing Search Operators**

| Operator | Description |
|----------|-------------|
| `"Search Term"` | Search for the exact phrase |
| `-term` | Remove pages mentioning a given term from results |
| `+term` | Force Google to include common words ordinarily discarded |
| `OR` | Search for term A OR term B |
| `site:` | Search within a given domain |
| `filetype:` | Search for a specific file type |
| `intitle:` | Pages with given word(s) in the page title |
| `inurl:` | Pages with given word(s) in the URL |
| `intext:` | Pages with given word(s) in the page body text |
| `inanchor:` | Pages that have given word(s) in links pointing to them |
| `cache:` | Show most recent cached version of a webpage |
| `IP:` | **Bing only** — find results based on a given IP address |
| `linkfromdomain:` | **Bing only** — search for links on a given domain |

**Additional Google Features:**
- **Search Tools → Custom Range:** Narrow results to a specific time frame — useful for finding recent disclosures or old exposed content
- **Google Images:** Reverse image search — https://images.google.com/

## 10.2 Searching for Archived Information

| Service | URL | Notes |
|---------|-----|-------|
| Google/Bing cache | Via search operator `cache:` | Quick snapshot of last indexed version |
| Wayback Machine | http://archive.org/web/ | Historical snapshots, old config files, removed pages |
| Archive Today | http://archive.is/ | On-demand archiving; useful for capturing current state |

## 10.3 Yandex

Yandex is the largest search engine in Russia (~65% market share) and often indexes content not found on Google/Bing.

**Yandex Search Operators**

| Example | Description |
|---------|-------------|
| `"I * music"` | Wildcard: find results with any word where `*` is located |
| `Cheshire cat \| hatter \| Alice` | OR search — any word in query (also works in Google) |
| `croquet +flamingo` | Mandate the page has "flamingo" but not necessarily "croquet" |
| `rhost:org.wikipedia.*` | Reverse host search |
| `mime:pdf` | Search for specific file type |
| `!Curiouser !and !curiouser` | Search for multiple identical words |
| `Twinkle twinkle little -star` | Exclude "star" from search results |
| `lang:en` | Narrow search by language |
| `date:200712*` | Search within a specific month |
| `date:20071215..20080101` | Search within a date range |
| `date:>20091231` | Search after a given date |

## 10.4 Alternative Search Engines

| Engine | URL | Strength |
|--------|-----|---------|
| Carrot2 | carrot2.org | Clustering engine — groups results into topic sets |
| Exalead | www.exalead.com/search | Strong for documents containing the search term |
| Million Short | millionshort.com | Remove top 1M popular sites from results — surfaces hidden content |
| Global File Search | globalfilesearch.com | 243 TB of files indexed on public FTP servers |

## 10.5 Shodan Filters (Full Reference)

| Filter | Description |
|--------|-------------|
| `city:` | Search for results in a given city |
| `country:` | Search by country (2-letter code, e.g. `country:ES`) |
| `port:` | Search for a specific port (e.g. `port:22`) |
| `hostname:` | Match hostname values |
| `net:` | Search a given IP or subnet (e.g. `net:192.168.1.0/24`) |
| `product:` | Name of software identified in the banner |
| `version:` | Version of the product |
| `os:` | Specific operating system name |
| `title:` | Search in HTML `<title>` tag content |
| `html:` | Search in full HTML contents of the returned page |
| `org:` | Search by organization name |
| `ssl:` | Search in SSL certificate fields |

## 10.6 Social Networks — Facebook

**Profile Lookup by Email/Phone:** Use the Facebook search bar to find profiles registered with a given email or phone number.

**Find Facebook UserID:**
- https://findmyfbid.com
- While logged in: inspect page source and look for `fb://profile/<UserID>`

**Facebook Graph Search Queries** — append to `https://www.facebook.com`:

| Category | Graph URL |
|----------|-----------|
| Places | `/search/UserID/places` |
| Places visited | `/search/UserID/places-visited` |
| Places recently visited | `/search/UserID/recent-places-visited` |
| Places checked in | `/search/UserID/places-checked-in` |
| Places liked | `/search/UserID/places-liked` |
| Pages liked | `/search/UserID/pages-liked` |
| Photos | `/search/UserID/photos` |
| Photos of | `/search/UserID/photos-of` |
| Photos by | `/search/UserID/photos-by` |
| Photos liked | `/search/UserID/photos-liked` |
| Photos commented | `/search/UserID/photos-commented` |
| Apps used | `/search/UserID/apps` |
| Videos | `/search/UserID/videos` |
| Videos of | `/search/UserID/videos-of` |
| Videos by | `/search/UserID/videos-by` |
| Videos liked | `/search/UserID/videos-liked` |
| Videos commented | `/search/UserID/videos-commented` |
| Events | `/search/UserID/events` |
| Events in specific year | `/search/str/UserID/events-joined/2010/date/events/intersect/` |
| Posts by | `/search/UserID/stories-by` |
| Posts tagged | `/search/UserID/stories-tagged` |
| Posts liked | `/search/UserID/stories-liked` |
| Posts by year | `/search/UserID/stories-by/2010/date/stories/intersect` |
| Friends | `/search/UserID/friends` |
| Relatives | `/search/UserID/relatives` |
| Followers | `/search/UserID/followers` |
| Groups | `/search/UserID/groups` |
| Employers | `/search/UserID/employers` |
| Co-workers | `/search/UserID/employees` |
| Page likers | `/likers` |

Additional FB graph queries: https://inteltechniques.com/osint/menu.facebook.html and http://researchclinic.net/graph.html

## 10.7 Social Networks — Twitter/X Search Operators

| Operator | Finds Tweets… |
|----------|--------------|
| `twitter search` | Containing both "twitter" and "search" (default AND) |
| `"happy hour"` | Containing the exact phrase "happy hour" |
| `love OR hate` | Containing "love" or "hate" (or both) |
| `beer -root` | Containing "beer" but not "root" |
| `#haiku` | Containing the hashtag "haiku" |
| `from:username` | Sent from a specific user |
| `to:username` | Sent to a specific user |
| `@username` | Referencing a specific user |
| `"phrase" near:"city"` | Exact phrase sent from a specific city |
| `near:NYC within:15mi` | Sent from within 15 miles of NYC |
| `term since:2010-12-27` | Containing term, sent since that date |
| `term until:2010-12-27` | Containing term, sent up to that date |
| `term filter:links` | Containing term and linking to URLs |
| `news source:"Twitter Lite"` | Containing "news" entered via Twitter Lite |
| `geocode:47.37,8.541,10km` | Sent from within 10km of a specific coordinate |

Additional Twitter search: https://twitter.com/search-advanced and https://inteltechniques.com/osint/twitter.html

## 10.8 Social Network User Enumeration

Different features across platforms can confirm whether an account/email is registered:

| Method | Twitter | Facebook | Instagram | LinkedIn | Xing |
|--------|---------|----------|-----------|----------|------|
| Registration form | X | X | X | X | X |
| Password forgotten | X | X | X | X | X |
| Search bar | — | X | — | — | — |

> **Note:** The "password forgotten" feature on Facebook and Twitter also **discloses the last 2 digits of the registered mobile number** — useful for further OSINT.

## 10.9 Key OSINT Tools (Compass Reference)

| Tool | URL | Description |
|------|-----|-------------|
| Maltego | — | Extremely powerful OSINT framework for infrastructural and personal recon; entity-link graph visualization |
| FOCA | https://www.elevenpaths.com | Extracts metadata and hidden information from documents found on web pages |
| Intel Techniques | https://inteltechniques.com | Swiss Army Knife for OSINT — aggregates dozens of search tools |
| Robtex | https://www.robtex.com | Multi-source lookup for IPs, domains, hostnames, ASNs, routes |

## 10.10 Recommended Books

- **Google Hacking for Penetration Testers** — Johnny Long
- **Open Source Intelligence Techniques** — Michael Bazzell
- **Privacy and Security** — Michael Bazzell
- **Hiding from the Internet** — Michael Bazzell
