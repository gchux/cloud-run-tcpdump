--- fs.go	2025-01-08 23:54:23.593793132 +0000
+++ fs_cloud_run_gen1.go	2025-01-08 23:53:20.664160603 +0000
@@ -1303,7 +1303,8 @@
 	tmp := fs.inodes[id]
 	in, ok := tmp.(*inode.FileInode)
 	if !ok {
-		panic(fmt.Sprintf("inode %d is %T, wanted *inode.FileInode", id, tmp))
+		// panic(fmt.Sprintf("inode %d is %T, wanted *inode.SymlinkInode", id, tmp))
+		return nil
 	}
 
 	return
@@ -1318,7 +1319,8 @@
 	tmp := fs.inodes[id]
 	in, ok := tmp.(*inode.SymlinkInode)
 	if !ok {
-		panic(fmt.Sprintf("inode %d is %T, wanted *inode.SymlinkInode", id, tmp))
+		// panic(fmt.Sprintf("inode %d is %T, wanted *inode.SymlinkInode", id, tmp))
+		return nil
 	}
 
 	return
@@ -2542,6 +2544,10 @@
 	in := fs.fileInodeOrDie(op.Inode)
 	fs.mu.Unlock()
 
+	if in == nil {
+		return nil
+	}
+
 	in.Lock()
 	defer in.Unlock()
 
