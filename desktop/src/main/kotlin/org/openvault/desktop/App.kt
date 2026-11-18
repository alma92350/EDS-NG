package org.openvault.desktop

import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.io.File
import javax.swing.*

class MainWindow : JFrame("OpenVault") {
    private val model = DefaultListModel<String>()
    private val list = JList(model)
    private val status = JLabel(" ")

    init {
        defaultCloseOperation = EXIT_ON_CLOSE
        jMenuBar = JMenuBar().apply {
            add(JMenu("File").apply { add(JMenuItem("Open container…").apply { addActionListener { chooseContainer() } }); add(JMenuItem("Exit").apply { addActionListener { Sessions.lockAll(); dispose(); System.exit(0) } }) })
            add(JMenu("Vault").apply { add(JMenuItem("Lock all").apply { addActionListener { Sessions.lockAll() } }) })
            add(JMenu("Auto-lock").apply {
                val g = ButtonGroup()
                for ((label, ms) in listOf("1 minute" to 60_000L, "5 minutes" to 300_000L, "15 minutes" to 900_000L, "1 hour" to 3_600_000L, "Never" to 0L))
                    add(JRadioButtonMenuItem(label, Sessions.policy.timeoutMs == ms).apply { g.add(this); addActionListener { Sessions.setTimeout(ms) } })
            })
            add(JMenu("Help").apply { add(JMenuItem("About").apply { addActionListener { JOptionPane.showMessageDialog(this@MainWindow,
                "OpenVault 0.1.1 (test build)\nGPL-3.0-or-later. Clean-room VeraCrypt/TrueCrypt container reader and writer.\n\nNo network access. Vaults lock after inactivity.\nKeep backups of containers; prefer read-only mode.", "About", JOptionPane.INFORMATION_MESSAGE) } }) })
        }
        val top = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS); border = BorderFactory.createEmptyBorder(10, 10, 6, 10)
            add(JLabel("<html><b>Open a VeraCrypt or TrueCrypt container file</b> (FAT12/16/32 or exFAT, AES).<br>Only its path is remembered, never passwords.</html>").apply { alignmentX = 0f })
            add(Box.createVerticalStrut(8))
            add(JPanel().apply { alignmentX = 0f; layout = BoxLayout(this, BoxLayout.X_AXIS)
                add(JButton("Open container…").apply { addActionListener { chooseContainer() } }); add(Box.createHorizontalStrut(8))
                add(JButton("Remove from list").apply { addActionListener { list.selectedValue?.let { Sessions.removeRecent(it); reload() } } }); add(Box.createHorizontalGlue()) })
        }
        add(top, BorderLayout.NORTH)
        add(JScrollPane(list).apply { border = BorderFactory.createTitledBorder("Recent containers (double-click to unlock)") }, BorderLayout.CENTER)
        add(status.apply { border = BorderFactory.createEmptyBorder(4, 10, 6, 10) }, BorderLayout.SOUTH)
        list.addMouseListener(object : MouseAdapter() { override fun mouseClicked(e: MouseEvent) { if (e.clickCount == 2) list.selectedValue?.let { unlock(File(it)) } } })
        Sessions.listeners.add { SwingUtilities.invokeLater { refresh() } }
        reload(); size = Dimension(720, 440); setLocationRelativeTo(null)
    }

    private fun reload() { model.clear(); Sessions.recent().forEach { model.addElement(it) }; refresh() }
    private fun refresh() { status.text = if (Sessions.count == 0) "No vault unlocked." else "${Sessions.count} vault(s) unlocked. Auto-lock after ${if (Sessions.policy.timeoutMs <= 0) "never" else "${Sessions.policy.timeoutMs / 60000} min"} of inactivity." }

    private fun chooseContainer() {
        val fc = JFileChooser().apply { dialogTitle = "Choose a VeraCrypt/TrueCrypt container file" }
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) unlock(fc.selectedFile)
    }

    private fun unlock(file: File) {
        if (!file.isFile) return JOptionPane.showMessageDialog(this, "File not found:\n$file").also { Sessions.removeRecent(file.path); reload() }.let { }
        val dlg = UnlockDialog(this, file); dlg.isVisible = true
        val req = dlg.result ?: return
        val busy = Busy(this, "Unlocking", "Deriving keys…"); busy.show()
        Thread {
            val out = Unlocker.open(req, { busy.cancelled.get() }) { d, t -> busy.message("Header attempt $d of $t…") }
            SwingUtilities.invokeLater {
                busy.close()
                when (out) {
                    is UnlockOutcome.Opened -> {
                        Sessions.addRecent(file.path); reload()
                        val frame = JFrame("${out.session.name} - OpenVault${if (out.session.readOnly) " (read-only)" else ""}").apply {
                            defaultCloseOperation = DO_NOTHING_ON_CLOSE
                            add(BrowserPanel(out.session)); size = Dimension(900, 620); setLocationRelativeTo(this@MainWindow)
                        }
                        frame.addWindowListener(object : java.awt.event.WindowAdapter() { override fun windowClosing(e: java.awt.event.WindowEvent) { out.session.lock(); Sessions.remove(out.session); frame.dispose() } })
                        Sessions.add(out.session, frame); frame.isVisible = true
                        out.warning?.let { JOptionPane.showMessageDialog(frame, it, "Notice", JOptionPane.INFORMATION_MESSAGE) }
                    }
                    is UnlockOutcome.Failed -> JOptionPane.showMessageDialog(this, out.message, "Cannot unlock", JOptionPane.ERROR_MESSAGE)
                    is UnlockOutcome.Cancelled -> status.text = "Cancelled."
                }
            }
        }.start()
    }
}

/** Test-build diagnostics: show unexpected exceptions (stack trace only, no vault data) so they can be copied into a bug report. */
private fun installCrashDialog() {
    Thread.setDefaultUncaughtExceptionHandler { t, e ->
        val trace = java.io.StringWriter().also { e.printStackTrace(java.io.PrintWriter(it)) }.toString()
        val text = "OpenVault 0.1.1-test\n${System.getProperty("os.name")} ${System.getProperty("os.version")}, Java ${System.getProperty("java.version")}\nthread: ${t.name}\n\n$trace"
        SwingUtilities.invokeLater {
            val area = JTextArea(text.take(8000)).apply { isEditable = false; font = java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 11) }
            JOptionPane.showMessageDialog(null, JScrollPane(area).apply { preferredSize = Dimension(700, 400) }, "OpenVault - unexpected error (you can copy this text)", JOptionPane.ERROR_MESSAGE)
        }
    }
}

fun main() {
    installCrashDialog()
    runCatching { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()) }
    SwingUtilities.invokeLater { MainWindow().isVisible = true }
}
