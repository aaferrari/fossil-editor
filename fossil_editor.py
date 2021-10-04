#!/usr/bin/env python
# -*- coding: utf-8 -*-

def sha3_import():
    for module in ["hashlib", "sha3"]:
        try: return import_module(module).sha3_256
        except (ImportError, AttributeError): pass
    """
    If it reaches here is why:
    * hashlib does not have sha3_256 (Python 3.5 and earlier).
    * The previous condition is fulfilled in addition to not having pysha3 installed.
    """
    print("ERROR: SHA3 not available. Install pysha3 instead.")
    exit(1)

import zlib, re
from hashlib import md5
from binascii import unhexlify
import sys, sqlite3, os
from importlib import import_module
sha3_256 = sha3_import()
if sys.version_info[0] >= 3:
    # Necessary to maintain compatibility with python 2
    buffer = lambda string: string.encode() if hasattr(string, "encode") else string

width_pattern = re.compile(b"\nW ([0-9]+)\n")
previous_edit_pattern = re.compile(b"\nP ([0-9a-f]{64})\n")
md5_pattern = re.compile(b"\nZ ([0-9a-f]{32})\n")
fossil_bin = "fossil"
delta_filename = "intermediate_delta"

# Function to get the hash of an artifact from a regular expression
def get_hash(pattern, metadata):
    found_hash = pattern.search(metadata)
    if found_hash != None: return found_hash.groups()[0]
    else: return ""

# Decompresion
def fossil_decompress(buffer, uncompressed = False):
    if uncompressed == False:
        result = zlib.decompress(buffer[4:])
    else: result = buffer
    content_size = width_pattern.search(result)
    content_start = content_size.end()
    content_end = content_start + int(content_size.groups()[0])
    unpacked = {}
    unpacked["content"] = result[content_start:content_end]
    unpacked["metadata"] = result[0:content_size.end()]
    # Use bytearray instead of strings in Python 2 to avoid character encoding problems.
    if sys.version_info[0] == 2:
        unpacked["content"] = bytearray(unpacked["content"])
        unpacked["metadata"] = bytearray(unpacked["metadata"])
    unpacked["prev"] = get_hash(previous_edit_pattern, unpacked["metadata"])
    unpacked["md5"] = get_hash(md5_pattern, result)
    return unpacked

# Returns the name of an article with certain escaped characters 
def sanitizer(name):
    return name.replace(" ", "\\s").encode()

# Recompression
def fossil_compress(artifact, is_delta = False):
    if is_delta == False:
        metadata = width_pattern.sub(b"\nW %i\n" % len(artifact["content"]), artifact["metadata"], 1)
        dehased_result = metadata + artifact["content"] + b"\n"
        content_md5 = md5(dehased_result).hexdigest()
        result = dehased_result + b"Z %s\n" % content_md5.encode()
    else: result = artifact
    packed= {}
    packed["size"] = len(result)
    # The first 4 bits are the size of the content in hexadecimal.
    # In artifacts it is just 4 bits for the size followed by the raw contents of the file
    bin_size = unhexlify(hex(packed["size"])[2:].zfill(8))
    packed["blob"] = buffer(bin_size + zlib.compress(buffer(result)))
    # Para actualizar el uuid asociado al artefacto
    packed["id"] = sha3_256(result).hexdigest()
    packed["md5"] = (content_md5 if is_delta == False else None)
    return packed

def article_renamer(old_name, new_name):
    query = """
    SELECT size, uuid, content FROM tagxref
     INNER JOIN blob ON blob.rid=tagxref.rid
     WHERE tagid=(SELECT tagid FROM tag
      WHERE tagname='wiki-%s')
     ORDER BY mtime
    """
    # Get the article and its intermediate editions from its first version to
    # the most recent 
    artifacts_data = cur_repo.execute(query % old_name).fetchall()
    if len(artifacts_data) == 0:
        return None
    # Original hash of the previous delta
    last_hash_delta = ""
    # Modified hash of the previous delta
    last_new_hash_delta = ""
    hash_list = []
    # Create modified files with all the issues of the article before starting
    # The name and hashes are updated to subsequently be able to get their deltas
    for artifact in artifacts_data:
        command_result = os.system("%s artifact %s -R %s > %s" % (fossil_bin, artifact[1], reponame, artifact[1]))
        hash_list.append(artifact[1])
        article_edit = open(artifact[1], "rb").read()
        article_edit = article_edit.replace(b"\nL %s\n" % sanitizer(old_name), b"\nL %s\n" % sanitizer(new_name))
        # Update the SHA3 hash of the previous edition
        if artifact != artifacts_data[0]:
            prev_artifact_hash = str(artifacts_data[artifacts_data.index(artifact) - 1][1])
            prev_updated = fossil_decompress(open(prev_artifact_hash, "rb").read(), True)
            article_edit = article_edit.replace(prev_artifact_hash.encode(), fossil_compress(prev_updated)["id"].encode(), 1)
        recompressed = fossil_compress(fossil_decompress(article_edit, True))
        article_edit = md5_pattern.sub(b"\nZ %s\n" % recompressed["md5"].encode(), article_edit, 1)
        edited_artifact = open(artifact[1], "wb")
        edited_artifact.write(article_edit)
        edited_artifact.close()
    for artifact in artifacts_data:
        # The last artifact contains the wiki article in its most recent version
        # The others are deltas that record the modifications made over time.
        if artifact != artifacts_data[-1]:
            next_hash = hash_list[hash_list.index(artifact[1]) + 1]
            cmd_delta = "%s test-delta-create %s %s '%s'" % (fossil_bin, next_hash, artifact[1], delta_filename)
            proc = os.system(cmd_delta)
            #print(cmd_delta)
            uncompressed_artifact = open(delta_filename, "rb").read()
            article_data = open(artifact[1], "rb").read()
            raw_artifact = fossil_decompress(article_data, True)
        else:
            raw_artifact = fossil_decompress(artifact[2])
            raw_artifact["metadata"] = raw_artifact["metadata"].replace(b"\nL %s\n" % sanitizer(old_name), b"\nL %s\n" % sanitizer(new_name))
            raw_artifact["metadata"] = raw_artifact["metadata"].replace(last_hash_delta.encode(), last_new_hash_delta)
        artifact_mod = fossil_compress(raw_artifact)
        if artifact != artifacts_data[-1]:
            # Replace the md5 hash of the original article
            #original_md5_hash = md5_pattern.search(article_data).group(1)
            #uncompressed_artifact = uncompressed_artifact.replace(original_md5_hash, artifact_mod["md5"])
            # Replace the SHA3 hash of the previous delta if it exists
            #uncompressed_artifact = uncompressed_artifact.replace(last_hash_delta, last_new_hash_delta)
            artifact_mod["blob"] = fossil_compress(uncompressed_artifact, True)["blob"]
        # Update artifact in the repo database
        update_statement = "UPDATE blob SET uuid = ?, size = ?, content = ? WHERE uuid = ?"
        cur_repo.execute(update_statement, [artifact_mod["id"], artifact_mod["size"], artifact_mod["blob"], artifact[1]])
        last_new_hash_delta = bytearray(artifact_mod["id"].encode())
        last_hash_delta = str(artifact[1])
        print("Artifact %s updated to %s" % (artifact[1][:10], artifact_mod["id"][:10]))
    # Update everything that points to the old article name
    cur_repo.execute("UPDATE attachment SET target=? WHERE target=?", [new_name, old_name])
    cur_repo.execute("UPDATE event SET comment=':%s' WHERE comment=':%s'" % (new_name, old_name))
    cur_repo.execute("UPDATE event SET comment='+%s' WHERE comment='+%s'" % (new_name, old_name))
    cur_repo.execute("UPDATE event SET comment=replace(comment, '[%s]', '[%s]') WHERE comment like '%%[%s]%%'" % (old_name, new_name, old_name))
    cur_repo.execute("UPDATE tag SET tagname='wiki-%s' WHERE tagname='wiki-%s'" % (new_name, old_name))
    print("References updated")
    # Delete temporary files after finishing
    for sha_hash in hash_list: os.remove(sha_hash)
    os.remove(delta_filename)
    return True

if __name__ == "__main__":
    try:
        original_name = sys.argv[1]
        new_name = sys.argv[2]
        reponame = sys.argv[3]
    except IndexError:
        print("Usage:\n  %s old_name new_name repo_file [fossil executable]" % sys.argv[0])
        exit()
    try: fossil_bin = sys.argv[4]
    except IndexError: pass
    # We check if the fossil executable is available.
    fossil_check = os.system("%s version" % fossil_bin)
    if fossil_check != 0:
        print("ERROR: fossil binary not available")
        exit(1)
    try: repodb = sqlite3.connect(reponame)
    except sqlite3.OperationalError:
        print("ERROR: invalid repository")
        exit(1)
    # Get SQL data query as dict
    #repodb.row_factory = sqlite3.Row
    cur_repo = repodb.cursor()
    #print("|".join(sys.argv))
    result = article_renamer(original_name, new_name)
    if result == None:
        print("ERROR: article not found")
        exit(1)
    repodb.commit()
    cur_repo.close()
    repodb.close()
