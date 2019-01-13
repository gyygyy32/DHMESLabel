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
    public partial class LabelPrint : Form
    {
        public LabelPrint()
        {
            InitializeComponent();
               
        }
        CRUD objCRUD = new CRUD(); 
        private void txtModuleID_KeyPress(object sender, KeyPressEventArgs e)
        {
            string strProductType;
            string strSizeWeight;
            string[] arySizeWeight;
            if (e.KeyChar == 13)
            {
                if (txtModuleID.Text == "")
                {
                    MessageBox.Show(this,"请扫描组件序列号！");
                        return;
                }
                DataTable dt = objCRUD.QueryPmaxByModuleID(txtModuleID.Text);
                if (dt == null)
                {
                    MessageBox.Show(this, "没有查询到该组件序列号！");
                    txtModuleID.Text = "";
                    return;
                }
                string strPmax = dt.Rows[0]["Pmax"].ToString();
                string realIsc = dt.Rows[0]["isc"].ToString();
                string realIpm = dt.Rows[0]["ipm"].ToString();
                //查询组件序列号的产品族&组件尺寸和重量 add by lei.xue on 2017-3-19==========================================
                dt = null;
                dt = objCRUD.QueryProductTypeByModuleLot(txtModuleID.Text);
                if (dt != null && dt.Rows.Count > 0)
                {
                    txtProductType.Text = dt.Rows[0]["producttype"].ToString();
                    strSizeWeight = dt.Rows[0]["sizeweight"].ToString();
                    arySizeWeight = strSizeWeight.Split(',');
                    if (arySizeWeight.Length >= 5)
                    {
                        txtSize.Text = arySizeWeight[3];
                        txtWeight.Text = arySizeWeight[4];
                    }
                }
                else
                {
                    MessageBox.Show("未查询到产品族、尺寸和重量信息");
                    return;
                }
                //查询组件序列号的产品族&组件尺寸和重量 add by lei.xue on 2017-3-19==========================================
                dt = objCRUD.QueryLabelInfo(strPmax,txtProductType.Text);
                if (dt != null && dt.Rows.Count > 0)
                {
                    txtPmax.Text = dt.Rows[0]["Pmax"].ToString();
                    txtVmp.Text = dt.Rows[0]["Vmp"].ToString();
                    txtVoc.Text = dt.Rows[0]["Voc"].ToString();
                    txtVolmax.Text = dt.Rows[0]["Volmax"].ToString();
                    txtModuleapp.Text = dt.Rows[0]["ModuleApp"].ToString();
                    txtFusemax.Text = dt.Rows[0]["Fusemax"].ToString();
                    txtIsc.Text = dt.Rows[0]["Isc"].ToString();
                    txtImp.Text = dt.Rows[0]["Imp"].ToString();

                    //查询电流挡位
                    string strGrade = objCRUD.QueryIGrade(txtProductType.Text, txtPmax.Text, realIsc, realIpm);//txtIsc.Text, txtImp.Text);
                    if (strGrade == "fail")
                    {
                        txtLog.Text = txtModuleID.Text+"未查询到电流配置信息" + "\r\n" + txtLog.Text;
                    }
                    else {
                        txtIGrade.Text = strGrade;
                    }
                }
                else
                {
                    MessageBox.Show("未查询到配置信息");
                    return;
                }

                if (System.DateTime.Now > Convert.ToDateTime("2019-3-20 19:00"))
                {
                    return;
                }

                btnPrint_Click(null,null);

                
            }
        }

        private void btnPrint_Click(object sender, EventArgs e)
        {
            //strWriteFileStream = wipDataReceived.Result;
            using (System.IO.StreamWriter file = new System.IO.StreamWriter(@"c:\BarcodePrint\ModuleLabel.txt", false, Encoding.GetEncoding("gb2312")))
            {
                file.WriteLine(txtPmax.Text+","+
                               //Convert.ToDouble(txtVmp.Text).ToString("0.0") + ","+ 
                               //Convert.ToDouble(txtImp.Text).ToString("0.00") +","+
                               //Convert.ToDouble(txtVoc.Text).ToString("0.0") +","+
                               //Convert.ToDouble(txtIsc.Text).ToString("0.00") +","+
                               txtVmp.Text+","+
                               txtImp.Text + "," +
                               txtVoc.Text + "," +
                               txtIsc.Text + "," +
                               txtVolmax.Text+","+
                               txtFusemax.Text+","+
                               txtModuleapp.Text+","+
                               txtProductType.Text+","+
                               txtWeight.Text+","+
                               txtSize.Text+","+
                               txtModuleID.Text+","+
                               txtIGrade.Text);
                file.Close();
            }

            string templateName = DDLTemplate.SelectedValue.ToString();
            using (System.IO.StreamWriter file = new System.IO.StreamWriter(@"c:\BarcodePrint\usb.bat", false, Encoding.GetEncoding("gb2312")))
            {
                file.WriteLine("@echo off");

                file.WriteLine("bartend.exe /F=\"C:\\BarcodePrint\\" + templateName + ".btw\" /D=\"C:\\BarcodePrint\\ModuleLabel.txt\" /P /x");
                //add by lei.xue on 2017-8-31 增加组件序列号标签
                file.WriteLine("bartend.exe /F=\"C:\\BarcodePrint\\" + "MouldLot" + ".btw\" /D=\"C:\\BarcodePrint\\ModuleLabel.txt\" /P /x"); 
            }

            txtLog.Text = txtModuleID.Text + "\r\n" + txtLog.Text;
            Clear();

            try
            {
                System.Diagnostics.Process.Start(@"c:\BarcodePrint\usb.bat");
            }
            catch (Exception)
            {
                throw;
            }
        }

       

        private void LabelPrint_Load(object sender, EventArgs e)
        {

            //RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            //string RSAPublic = rsa.ToXmlString(false);// RSA公钥
            //string RSAPrivate = rsa.ToXmlString(true);// RSA私钥
            //MessageBox.Show(RSAPublic);

            //RSACryptoServiceProvider rsa1 = new RSACryptoServiceProvider();
            //MessageBox.Show(rsa1.ToXmlString(false));

            DataTable dt = objCRUD.QueryTemplatePath();
            if (dt != null && dt.Rows.Count > 0)
            {
                DDLTemplate.DataSource = dt;
                DDLTemplate.DisplayMember = "PRIDISPLAYNAME";
                DDLTemplate.ValueMember = "PRISOURCENAME";
            }
        }

        private void Clear()
        {
            //txtPmax.Text = "";
            //txtVmp.Text = "";
            //txtVoc.Text = "";
            //txtVolmax.Text = "";
            //txtModuleapp.Text = "";
            //txtFusemax.Text = "";
            //txtIsc.Text = "";
            //txtImp.Text = "";
            txtModuleID.Text = "";
            //txtProductType.Text = "";
            //txtSize.Text = "";
            //txtWeight.Text = "";
        }

        

        
    }
}
