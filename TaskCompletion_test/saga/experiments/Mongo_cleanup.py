#!/usr/bin/env python3
import argparse
from pymongo import MongoClient


def build_query():
    # Same fingerprint as before, scoped to the final-results artifacts.
    return {
        "from": "Bob Smith <bob@mail.com>",
        "to": {"$all": ["hr@university.com", "emma_johnson@gmail.com", "bob@mail.com"]},
    }

DEFAULT_COLLECTIONS = [
    "hr@university.com_inbox",
    "bob@mail.com_sent",
    "bob@mail.com_inbox",
    "emma_johnson@gmail.com_inbox",
]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mongo-uri", required=True, help="e.g. mongodb://172.172.235.2:27017/saga_tools")
    ap.add_argument("--apply", action="store_true", help="Actually delete. Otherwise dry-run.")
    ap.add_argument("--limit", type=int, default=0, help="Optional safety cap per collection (0 means no cap).")
    ap.add_argument("--collections", nargs="*", default=DEFAULT_COLLECTIONS,
                    help="Collections to target inside db=email.")
    args = ap.parse_args()

    client = MongoClient(args.mongo_uri)
    email_db = client.get_database("email")
    q = build_query()

    mode = "APPLY (deleting)" if args.apply else "DRY-RUN (no deletes)"
    print(f"[purge] mode={mode}")
    print(f"[purge] uri={args.mongo_uri}")
    print(f"[purge] db=email")
    print(f"[purge] collections={args.collections}")

    total_matched = 0
    total_deleted = 0

    for cname in args.collections:
        col = email_db.get_collection(cname)

        matched = col.count_documents(q)
        total_matched += matched

        if not args.apply:
            print(f"  [db=email] {cname}: matched={matched} (dry-run)")
            continue

        if matched == 0:
            print(f"  [db=email] {cname}: matched=0 deleted=0")
            continue

        # Optional safety cap: delete at most N newest matches
        if args.limit and matched > args.limit:
            ids = list(col.find(q, {"_id": 1}).sort("time:", -1).limit(args.limit))
            id_list = [d["_id"] for d in ids]
            res = col.delete_many({"_id": {"$in": id_list}})
        else:
            res = col.delete_many(q)

        total_deleted += res.deleted_count
        print(f"  [db=email] {cname}: matched={matched} deleted={res.deleted_count}")

    print(f"[purge] DONE: matched={total_matched} deleted={total_deleted}")

if __name__ == "__main__":
    main()
