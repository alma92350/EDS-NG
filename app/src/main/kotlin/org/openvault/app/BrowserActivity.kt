package org.openvault.app

import android.app.Activity
import android.app.AlertDialog
import android.app.ProgressDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.*
import org.openvault.fs.*
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.atomic.AtomicBoolean

class BrowserActivity : Activity() {
    private var path = FsPath.ROOT
    private var items: List<FsNode> = emptyList()
    private lateinit var list: ListView
    private lateinit var header: TextView
    private var pendingExport: FsNode? = null
    private val onLock: () -> Unit = { runOnUiThread { finish() } }

    override fun onCreate(b: Bundle?) {
        super.onCreate(b); secure()
        if (Vault.session == null) { finish(); return }
        path = FsPath.parse(savedInstanceStatePath(b))
        header = label(this, "", 13f)
        list = ListView(this)
        setContentView(LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; addView(pad(header, 12)); addView(list, LinearLayout.LayoutParams(-1, 0, 1f)) })
        list.setOnItemClickListener { _, _, i, _ -> open(items[i]) }
        list.setOnItemLongClickListener { _, _, i, _ -> actions(items[i]); true }
        Vault.lockListeners.add(onLock)
        load()
    }

    private fun savedInstanceStatePath(b: Bundle?) = b?.getString("path") ?: "/"
    override fun onSaveInstanceState(o: Bundle) { super.onSaveInstanceState(o); o.putString("path", path.toString()) }
    override fun onDestroy() { Vault.lockListeners.remove(onLock); super.onDestroy() }
    override fun onUserInteraction() { Vault.activity() }

    private val ro get() = Vault.session?.readOnly ?: true

    private fun load() {
        val s = Vault.session ?: return finish()
        title = s.containerName
        Vault.io({ val n = s.fs.resolve(path); Triple(s.fs.list(n), s.fs.spaceInfo(), n) }) { r ->
            r.onSuccess { (nodes, space, _) ->
                items = nodes.sortedWith(compareBy({ !it.isDirectory }, { it.name.lowercase() }))
                header.text = "${path}   -   ${Names.size(space.freeBytes)} free of ${Names.size(space.totalBytes)}${if (ro) "   -   read-only" else ""}"
                val df = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                list.adapter = object : ArrayAdapter<FsNode>(this, android.R.layout.simple_list_item_2, android.R.id.text1, items) {
                    override fun getView(pos: Int, v: View?, p: ViewGroup): View {
                        val view = super.getView(pos, v, p); val n = items[pos]
                        (view.findViewById(android.R.id.text1) as TextView).text = (if (n.isDirectory) "[dir]  " else "") + n.name
                        (view.findViewById(android.R.id.text2) as TextView).text = (if (n.isDirectory) "" else Names.size(n.size) + "  -  ") + (n.modified?.let { df.format(Date(it.toEpochMilli())) } ?: "")
                        return view
                    }
                }
                if (items.isEmpty()) header.text = header.text.toString() + "\n(empty)"
            }.onFailure { reportError(it) }
        }
    }

    private fun open(n: FsNode) { if (n.isDirectory) { path = n.path; load() } else startActivity(Intent(this, ViewerActivity::class.java).putExtra("path", n.path.toString())) }

    override fun onBackPressed() { if (!path.isRoot) { path = path.parent; load() } else super.onBackPressed() }

    private fun actions(n: FsNode) {
        val labels = ArrayList<String>(); val acts = ArrayList<() -> Unit>()
        if (!n.isDirectory) { labels += "Open"; acts += { open(n) }; labels += "Export (decrypted copy)…"; acts += { confirmExport(n) } }
        if (!ro) { labels += "Rename"; acts += { prompt("Rename", n.name) { nn -> op({ Vault.session!!.fs.rename(n, nn.trim()) }) } }
                   labels += "Delete"; acts += { AlertDialog.Builder(this).setMessage("Delete ${n.name}?").setNegativeButton("Cancel", null).setPositiveButton("Delete") { _, _ -> op({ Vault.session!!.fs.delete(n) }) }.show() } }
        labels += "Properties"; acts += { AlertDialog.Builder(this).setTitle(n.name).setMessage("Path: ${n.path}\nSize: ${if (n.isDirectory) "-" else Names.size(n.size)}\nModified: ${n.modified ?: "-"}").setPositiveButton("OK", null).show() }
        AlertDialog.Builder(this).setTitle(n.name).setItems(labels.toTypedArray()) { _, i -> acts[i]() }.show()
    }

    private fun op(block: () -> Unit) = Vault.io(block) { r -> r.onFailure { reportError(it) }; load() }

    // ------------------------------------------------------------------ menu / import / export
    override fun onCreateOptionsMenu(m: Menu): Boolean {
        if (!ro) { m.add(0, 1, 0, "New folder"); m.add(0, 2, 1, "Import files…") }
        m.add(0, 3, 2, "Lock"); return true
    }

    override fun onOptionsItemSelected(i: MenuItem): Boolean {
        when (i.itemId) {
            1 -> prompt("New folder") { name -> op({ val s = Vault.session!!; s.fs.createDirectory(s.fs.resolve(path), name.trim()) }) }
            2 -> startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*").putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true), 10)
            3 -> Vault.lock()
        }
        return true
    }

    private fun confirmExport(n: FsNode) {
        AlertDialog.Builder(this).setTitle("Export decrypted copy").setMessage("The exported file will NOT be encrypted. Continue?").setNegativeButton("Cancel", null)
            .setPositiveButton("Choose location") { _, _ -> pendingExport = n; startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("application/octet-stream").putExtra(Intent.EXTRA_TITLE, n.name), 11) }.show()
    }

    override fun onActivityResult(req: Int, res: Int, data: Intent?) {
        if (res != RESULT_OK || data == null) return
        when (req) {
            10 -> {
                val uris = ArrayList<Uri>()
                data.clipData?.let { c -> for (k in 0 until c.itemCount) uris += c.getItemAt(k).uri } ?: data.data?.let { uris += it }
                importFiles(uris)
            }
            11 -> data.data?.let { exportTo(pendingExport ?: return, it) }
        }
    }

    private fun importFiles(uris: List<Uri>) {
        val cancelled = AtomicBoolean(false)
        val dlg = ProgressDialog(this).apply { setMessage("Importing…"); setCancelable(false); setButton(ProgressDialog.BUTTON_NEGATIVE, "Cancel") { _, _ -> cancelled.set(true) }; show() }
        val target = path
        Vault.io({
            val fs = Vault.session!!.fs; val dir = fs.resolve(target); var done = 0
            for (u in uris) {
                if (cancelled.get()) break
                val existing = fs.list(dir).map { it.name }
                val name = Names.keepBoth(u.displayName(this), existing)
                runOnUiThread { dlg.setMessage("Importing $name (${done + 1}/${uris.size})…") }
                val node = fs.createFile(dir, name)
                var ok = false
                try {
                    fs.open(node, OpenMode.READ_WRITE).use { f ->
                        contentResolver.openInputStream(u)!!.use { input ->
                            val buf = ByteArray(256 * 1024); var pos = 0L
                            while (!cancelled.get()) { val n = input.read(buf); if (n < 0) { ok = true; break }; f.write(pos, buf, 0, n); pos += n }
                        }
                    }
                } finally { if (!ok) runCatching { fs.delete(fs.resolve(target.child(name))) } } // cancelled or failed: no partial file
                fs.sync(); done++
            }
        }) { r -> dlg.dismiss(); r.onFailure { reportError(it) }; load() }
    }

    private fun exportTo(n: FsNode, uri: Uri) {
        val dlg = ProgressDialog(this).apply { setMessage("Exporting ${n.name}…"); setCancelable(false); show() }
        Vault.io({
            val fs = Vault.session!!.fs
            fs.open(fs.resolve(n.path), OpenMode.READ).use { f ->
                contentResolver.openOutputStream(uri, "w")!!.use { out -> val buf = ByteArray(256 * 1024); var pos = 0L
                    while (true) { val k = f.read(pos, buf, 0, buf.size); if (k < 0) break; out.write(buf, 0, k); pos += k } }
            }
        }) { r -> dlg.dismiss(); r.onSuccess { toast("Exported (not encrypted)") }.onFailure { reportError(it) } }
    }
}
