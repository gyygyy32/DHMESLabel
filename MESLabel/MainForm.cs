using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;

namespace MESLabel
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            
            
            InitializeComponent();
            
        }

        private void 铭牌打印ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            LabelPrint frmLabelPrint = new LabelPrint();
            frmLabelPrint.MdiParent = this;
            frmLabelPrint.Activate();
            frmLabelPrint.Show();
            frmLabelPrint.WindowState = FormWindowState.Maximized;
        }

        private void 信息配置ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            PrintConfig frmPrintConfig = new PrintConfig();
            frmPrintConfig.MdiParent = this;
            frmPrintConfig.Activate();
            frmPrintConfig.Show();
            frmPrintConfig.WindowState = FormWindowState.Maximized;
        }
    }
}
