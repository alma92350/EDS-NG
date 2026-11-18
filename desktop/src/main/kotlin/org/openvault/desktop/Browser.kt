package org.openvault.desktop

import org.openvault.fs.*
import java.awt.*
import java.awt.datatransfer.DataFlavor
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.io.ByteArrayInputStream
import java.io.File
import java.text.DateFormat
import java.util.Date
import javax.imageio.ImageIO
import javax.swing.*
import javax.swing.table.AbstractTableModel

/** File browser for one unlocked vault. Pure Swing panel (testable headless by painting it). */
class BrowserPanel(private val session: DesktopSession) : JPanel(BorderLayout()) {
    private var path = FsPath.ROOT
    private var items: List<FsNode> = emptyList()
    private val pathLabel = JLabel(" ")
    private val status = JLabel(" ")
    private val df = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
    private val model = object : AbstractTableModel() {
        private val cols = arrayOf("Name", "Size", "Modified")
        override fun getRowCount() = items.size
        override fun getColumnCount() = 3
        override fun getColumnName(c: Int) = cols[c]
        override fun getValueAt(r: Int, c: Int): Any = items[r].let { n -> when (c) { 0 -> n.name; 1 -> if (n.isDirectory) "" else Names.size(n.size); else -> n.modified?.let { df.format(Date(it.toEpochMilli())) } ?: "" } }
        override fun isCellEditable(r: Int, c: Int) = false
    }
    private val table = JTable(model).apply { setShowGrid(false); rowHeight = 22; selectionModel.selectionMode = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION
        columnModel.getColumn(0).cellRenderer = object : javax.swing.table.DefaultTableCellRenderer() {
            override fun getTableCellRendererComponent(t: JTable, v: Any?, sel: Boolean, foc: Boolean, r: Int, c: Int): Component {
                super.getTableCellRendererComponent(t, v, sel, foc, r, c)
                icon = items.getOrNull(t.convertRowIndexToModel(r))?.let { UIManager.getIcon(if (it.isDirectory) "FileView.directoryIcon" else "FileView.fileIcon") }
                return this
            }
        }
        columnModel.getColumn(0).preferredWidth = 420; columnModel.getColumn(1).preferredWidth = 90; columnModel.getColumn(2).preferredWidth = 150; fillsViewportHeight = true }
    private val upBtn = JButton("⬆ Up").apply { addActionListener { if (!path.isRoot) { path = path.parent; load() } } }
    private val owner: Window? get() = SwingUtilities.getWindowAncestor(this)

    init {
        val tools = JToolBar().apply { isFloatable = false }
        tools.add(upBtn); tools.addSeparator()
        if (!session.readOnly) {
            tools.add(JButton("Import…").apply { toolTipText = "Copy files/folders into this folder (or drag them onto the list)"; addActionListener { chooseImport() } })
            tools.add(JButton("New folder").apply { addActionListener { newFolder() } })
        }
        tools.add(JButton("Export…").apply { toolTipText = "Save decrypted copies outside the vault"; addActionListener { export() } })
        if (!session.readOnly) {
            tools.add(JButton("Rename").apply { addActionListener { rename() } })
            tools.add(JButton("Delete").apply { addActionListener { delete() } })
        }
        tools.addSeparator(); tools.add(pathLabel)
        add(tools, BorderLayout.NORTH)
        val scroll = JScrollPane(table); add(scroll, BorderLayout.CENTER)
        add(status.apply { border = BorderFactory.createEmptyBorder(4, 8, 4, 8) }, BorderLayout.SOUTH)
        table.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) { if (e.clickCount == 2 && table.selectedRow >= 0) open(items[table.selectedRow]) }
            override fun mousePressed(e: MouseEvent) = popup(e)
            override fun mouseReleased(e: MouseEvent) = popup(e)
        })
        table.inputMap.put(KeyStroke.getKeyStroke("DELETE"), "del"); table.actionMap.put("del", object : AbstractAction() { override fun actionPerformed(e: java.awt.event.ActionEvent?) { if (!session.readOnly) delete() } })
        if (!session.readOnly) { val th = DropHandler(); table.transferHandler = th; scroll.transferHandler = th; scroll.viewport.transferHandler = th }
        load()
    }

    private fun selected(): List<FsNode> = table.selectedRows.map { items[table.convertRowIndexToModel(it)] }

    private fun popup(e: MouseEvent) {
        if (!e.isPopupTrigger) return
        val row = table.rowAtPoint(e.point); if (row >= 0 && !table.isRowSelected(row)) table.setRowSelectionInterval(row, row)
        val m = JPopupMenu()
        selected().singleOrNull()?.let { n -> m.add(JMenuItem("Open").apply { addActionListener { open(n) } }) }
        m.add(JMenuItem("Export…").apply { addActionListener { export() } })
        if (!session.readOnly) { m.add(JMenuItem("Rename").apply { addActionListener { rename() } }); m.add(JMenuItem("Delete").apply { addActionListener { delete() } }) }
        m.add(JMenuItem("Properties").apply { addActionListener { properties() } })
        m.show(table, e.x, e.y)
    }

    fun load() {
        session.async({ fs -> Triple(fs.list(fs.resolve(path)), fs.spaceInfo(), fs.label) }) { r ->
            r.onSuccess { (nodes, space, label) ->
                items = nodes.sortedWith(compareBy({ !it.isDirectory }, { it.name.lowercase() }))
                model.fireTableDataChanged(); upBtn.isEnabled = !path.isRoot
                pathLabel.text = "  $path"
                status.text = "${items.size} item(s)  |  ${Names.size(space.freeBytes)} free of ${Names.size(space.totalBytes)}" + (if (session.readOnly) "  |  READ-ONLY" else "") + (if (session.protection != null) "  |  hidden volume protected" else "") + (label?.let { "  |  $it" } ?: "")
            }.onFailure { error(it) }
        }
    }

    private fun error(t: Throwable) {
        var c: Throwable? = t
        while (c != null) { if (c is org.openvault.veracrypt.HiddenVolumeProtectionException) {
            JOptionPane.showMessageDialog(owner, "This write would have overwritten the hidden volume. The vault is now read-only; nothing was damaged.\nLock and unlock again to continue reading.", "Write refused", JOptionPane.WARNING_MESSAGE); return }; c = c.cause }
        JOptionPane.showMessageDialog(owner, t.message ?: t.javaClass.simpleName, "Error", JOptionPane.ERROR_MESSAGE)
    }

    private fun open(n: FsNode) {
        if (n.isDirectory) { path = n.path; load(); return }
        val ext = n.name.substringAfterLast('.', "").lowercase()
        val isImage = ext in setOf("png", "jpg", "jpeg", "gif", "bmp")
        val limit = if (isImage) 40L shl 20 else 5L shl 20
        session.async({ fs -> Transfer.readBytes(fs, n.path, limit) }) { r ->
            r.onFailure { error(it) }.onSuccess { bytes -> Viewer.show(owner, n.name, bytes, isImage) }
        }
    }

    private fun chooseImport() {
        val fc = JFileChooser().apply { isMultiSelectionEnabled = true; fileSelectionMode = JFileChooser.FILES_AND_DIRECTORIES; dialogTitle = "Import into ${path}" }
        if (fc.showOpenDialog(owner) == JFileChooser.APPROVE_OPTION) importFiles(fc.selectedFiles.toList())
    }

    fun importFiles(files: List<File>) {
        val busy = Busy(owner, "Importing", "Importing…"); busy.show(); val target = path
        session.async({ fs -> files.sumOf { f -> Transfer.importPath(fs, target, f, { busy.cancelled.get() }) { busy.message("Importing $it…") } } }) { r ->
            busy.close(); r.onFailure { error(it) }.onSuccess { if (busy.cancelled.get()) status.text = "Import cancelled ($it file(s) copied)" }; load()
        }
    }

    private fun newFolder() {
        val name = JOptionPane.showInputDialog(owner, "Folder name:", "New folder", JOptionPane.PLAIN_MESSAGE)?.trim() ?: return
        val target = path
        session.async({ fs -> fs.createDirectory(fs.resolve(target), name) }) { r -> r.onFailure { error(it) }; load() }
    }

    private fun rename() {
        val n = selected().singleOrNull() ?: return JOptionPane.showMessageDialog(owner, "Select one item to rename.").let { }
        val name = JOptionPane.showInputDialog(owner, "New name:", n.name)?.trim() ?: return
        session.async({ fs -> fs.rename(fs.resolve(n.path), name) }) { r -> r.onFailure { error(it) }; load() }
    }

    private fun delete() {
        val sel = selected(); if (sel.isEmpty()) return
        if (JOptionPane.showConfirmDialog(owner, "Delete ${sel.size} item(s)? Folders must be empty.", "Delete", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE) != JOptionPane.OK_OPTION) return
        session.async({ fs -> sel.forEach { fs.delete(fs.resolve(it.path)) } }) { r -> r.onFailure { error(it) }; load() }
    }

    private fun export() {
        val sel = selected(); if (sel.isEmpty()) return JOptionPane.showMessageDialog(owner, "Select files or folders to export.").let { }
        if (JOptionPane.showConfirmDialog(owner, "Exported copies are NOT encrypted. Continue?", "Export", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE) != JOptionPane.OK_OPTION) return
        val fc = JFileChooser().apply { fileSelectionMode = JFileChooser.DIRECTORIES_ONLY; dialogTitle = "Export to folder" }
        if (fc.showSaveDialog(owner) != JFileChooser.APPROVE_OPTION) return
        val dest = fc.selectedFile; val busy = Busy(owner, "Exporting", "Exporting…"); busy.show()
        session.async({ fs -> sel.sumOf { Transfer.exportTo(fs, fs.resolve(it.path), dest, { busy.cancelled.get() }) { n -> busy.message("Exporting $n…") } } }) { r ->
            busy.close(); r.onFailure { error(it) }.onSuccess { status.text = "Exported $it file(s) to ${dest.path} (not encrypted)" }
        }
    }

    private fun properties() {
        val n = selected().singleOrNull() ?: return
        JOptionPane.showMessageDialog(owner, "Name: ${n.name}\nPath: ${n.path}\nType: ${if (n.isDirectory) "folder" else "file"}\nSize: ${if (n.isDirectory) "-" else Names.size(n.size) + " (${n.size} bytes)"}\nModified: ${n.modified ?: "-"}", "Properties", JOptionPane.INFORMATION_MESSAGE)
    }

    private inner class DropHandler : TransferHandler() {
        override fun canImport(s: TransferSupport) = s.isDrop && s.isDataFlavorSupported(DataFlavor.javaFileListFlavor)
        @Suppress("UNCHECKED_CAST")
        override fun importData(s: TransferSupport): Boolean {
            if (!canImport(s)) return false
            val files = (s.transferable.getTransferData(DataFlavor.javaFileListFlavor) as List<File>)
            SwingUtilities.invokeLater { importFiles(files) }; return true
        }
    }
}

object Viewer {
    fun show(owner: Window?, name: String, bytes: ByteArray, image: Boolean) {
        val d = JDialog(owner, name, Dialog.ModalityType.MODELESS)
        if (image) {
            val img = ImageIO.read(ByteArrayInputStream(bytes)) ?: return JOptionPane.showMessageDialog(owner, "Cannot decode this image.").let { }
            d.add(JScrollPane(JLabel(ImageIcon(img))))
        } else {
            if (bytes.take(4096).any { it.toInt() == 0 }) return JOptionPane.showMessageDialog(owner, "No built-in viewer for this file type. Use Export.").let { }
            d.add(JScrollPane(JTextArea(String(bytes, Charsets.UTF_8)).apply { isEditable = false; font = Font(Font.MONOSPACED, Font.PLAIN, 13); caretPosition = 0 }))
        }
        d.setSize(900, 650); d.setLocationRelativeTo(owner); d.isVisible = true
    }
}
