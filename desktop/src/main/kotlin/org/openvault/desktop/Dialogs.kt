package org.openvault.desktop

import java.awt.*
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import javax.swing.*

/** Modal unlock form; returns null if cancelled. Fields are never persisted. */
class UnlockDialog(owner: Window?, private val file: File) : JDialog(owner, "Unlock ${file.name}", ModalityType.APPLICATION_MODAL) {
    var result: UnlockRequest? = null
        private set
    private val pw = JPasswordField(24)
    private val pim = JTextField(6)
    private val kfModel = DefaultListModel<File>()
    private val readOnly = JCheckBox("Open read-only (recommended)", true)
    private val tc = JCheckBox("TrueCrypt mode (legacy: RIPEMD-160, SHA-512, Whirlpool; no PIM)")
    private val all = JCheckBox("Try all hash algorithms (slower: adds Whirlpool, Streebog)")
    private val protect = JCheckBox("Protect hidden volume while writing")
    private val hpw = JPasswordField(24)

    init {
        val form = JPanel(GridBagLayout()); form.border = BorderFactory.createEmptyBorder(12, 12, 12, 12)
        val c = GridBagConstraints().apply { gridx = 0; gridy = 0; anchor = GridBagConstraints.WEST; fill = GridBagConstraints.HORIZONTAL; weightx = 1.0; insets = Insets(3, 3, 3, 3); gridwidth = 2 }
        fun row(comp: Component) { form.add(comp, c); c.gridy++ }
        row(JLabel("Password:")); row(pw)
        val pimRow = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply { add(JLabel("PIM (optional): ")); add(pim) }; row(pimRow)
        row(JLabel("Keyfiles (order does not matter):"))
        val list = JList(kfModel).apply { visibleRowCount = 3 }
        row(JScrollPane(list).apply { preferredSize = Dimension(360, 60) })
        val kfButtons = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0)).apply {
            add(JButton("Add keyfile…").apply { addActionListener { JFileChooser().also { fc -> fc.isMultiSelectionEnabled = true; if (fc.showOpenDialog(this@UnlockDialog) == JFileChooser.APPROVE_OPTION) fc.selectedFiles.forEach { kfModel.addElement(it) } } } })
            add(JButton("Remove").apply { addActionListener { list.selectedValuesList.forEach { kfModel.removeElement(it) } } })
        }; row(kfButtons)
        row(readOnly); row(tc); row(all); row(protect); hpw.isVisible = false; row(hpw)
        tc.addActionListener { pim.isEnabled = !tc.isSelected; all.isEnabled = !tc.isSelected; if (tc.isSelected) pim.text = "" }
        readOnly.addActionListener { protect.isEnabled = !readOnly.isSelected; if (readOnly.isSelected) { protect.isSelected = false; hpw.isVisible = false; pack() } }
        protect.isEnabled = false
        protect.addActionListener { hpw.isVisible = protect.isSelected; pack() }
        val ok = JButton("Unlock").apply { addActionListener { submit() } }
        val cancel = JButton("Cancel").apply { addActionListener { dispose() } }
        val buttons = JPanel(FlowLayout(FlowLayout.RIGHT)).apply { add(ok); add(cancel) }
        contentPane.add(form, BorderLayout.CENTER); contentPane.add(buttons, BorderLayout.SOUTH)
        rootPane.defaultButton = ok
        pack(); setLocationRelativeTo(owner)
    }

    private fun submit() {
        val p = pw.password
        if (p.isEmpty() && kfModel.isEmpty) { JOptionPane.showMessageDialog(this, "Enter a password and/or add a keyfile."); return }
        result = UnlockRequest(file, p, pim.text.trim().toIntOrNull() ?: 0, kfModel.elements().toList(), readOnly.isSelected, tc.isSelected, all.isSelected,
            if (protect.isSelected) hpw.password else null)
        pw.text = ""; hpw.text = ""
        dispose()
    }
}

/** Small non-modal progress window with a Cancel button. */
class Busy(owner: Window?, title: String, message: String) {
    val cancelled = AtomicBoolean(false)
    private val label = JLabel(message)
    private val dialog = JDialog(owner, title, Dialog.ModalityType.MODELESS).apply {
        defaultCloseOperation = WindowConstants.DO_NOTHING_ON_CLOSE
        val bar = JProgressBar().apply { isIndeterminate = true }
        contentPane.layout = BorderLayout(8, 8)
        (contentPane as JComponent).border = BorderFactory.createEmptyBorder(12, 12, 12, 12)
        add(label, BorderLayout.NORTH); add(bar, BorderLayout.CENTER)
        add(JButton("Cancel").apply { addActionListener { cancelled.set(true); text = "Cancelling…"; isEnabled = false } }, BorderLayout.SOUTH)
        setSize(380, 140); setLocationRelativeTo(owner)
    }
    fun show() { dialog.isVisible = true }
    fun message(m: String) = SwingUtilities.invokeLater { label.text = m }
    fun close() = SwingUtilities.invokeLater { dialog.dispose() }
}
