using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace MESLabel
{
    public partial class PrintConfig : Form
    {
        public PrintConfig()
        {
            InitializeComponent();
        }
        CRUD crud = new CRUD();
        private void PrintConfig_Load(object sender, EventArgs e)
        {
            #region "设置表格格式"
            grd.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.AllCells;
            grd.ColumnHeadersDefaultCellStyle.WrapMode = DataGridViewTriState.False;  //设置列标题不换行
            grd.Font = new Font("宋体", 12, FontStyle.Regular);
            grd.RowHeadersDefaultCellStyle.Alignment = System.Windows.Forms.DataGridViewContentAlignment.MiddleCenter;//设置列标题居中
            grd.AllowUserToAddRows = false;
            grd.ReadOnly = true;

            //grd.Columns.Add("Pmax", "功率");
            //grd.Columns.Add("linkdescription", "项目ID");


            #endregion
            databind();
        }

        private void databind()
        {
            grd.DataSource = crud.QueryConfig();
        }

        private void grd_CellClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0) return;
            if (e.ColumnIndex < 0) return;
            txtPmax.Text = grd.Rows[e.RowIndex].Cells["Pmax"].Value.ToString();
            txtVmp.Text = grd.Rows[e.RowIndex].Cells["Vmp"].Value.ToString();
            txtImp.Text = grd.Rows[e.RowIndex].Cells["Imp"].Value.ToString();
            txtVoc.Text = grd.Rows[e.RowIndex].Cells["Voc"].Value.ToString();
            txtIsc.Text = grd.Rows[e.RowIndex].Cells["Isc"].Value.ToString();
            txtVolmax.Text = grd.Rows[e.RowIndex].Cells["Volmax"].Value.ToString();
            txtFusemax.Text = grd.Rows[e.RowIndex].Cells["Fusemax"].Value.ToString();
            txtModuleApp.Text = grd.Rows[e.RowIndex].Cells["ModuleApp"].Value.ToString();
            txtUpperPower.Text = grd.Rows[e.RowIndex].Cells["UpperPower"].Value.ToString();
            txtLowerPower.Text = grd.Rows[e.RowIndex].Cells["LowerPower"].Value.ToString();
            //增加产品族 add by lei.xue on 2017-7-30
            txtProductType.Text = grd.Rows[e.RowIndex].Cells["ProductType"].Value.ToString();
            ddlIType.Text = grd.Rows[e.RowIndex].Cells["IType"].Value.ToString();
            txtIGrade.Text = grd.Rows[e.RowIndex].Cells["IGrade"].Value.ToString();
            txtLowerIPM.Text = grd.Rows[e.RowIndex].Cells["LOWERIMP"].Value.ToString();
            txtUpperIPM.Text = grd.Rows[e.RowIndex].Cells["UPPERIMP"].Value.ToString();

        }

        private void btnAdd_Click(object sender, EventArgs e)
        {
            if (txtFusemax.Text =="" ||
                txtImp.Text== "" ||
                txtIsc.Text == "" ||
                txtLowerPower.Text  ==""||
                txtModuleApp.Text==""||
                txtPmax.Text == "" ||
                txtUpperPower.Text ==""||
                txtVmp.Text ==""||
                txtVoc.Text ==""||
                txtVolmax.Text ==""
                )
            {
                MessageBox.Show("请先输入参数!");
                return;
            }


            //=====电流合法性检查==========================
            if (ddlIType.Text == "")
            {
                txtIGrade.Text = "";
                txtLowerIPM.Text = "";
                txtUpperIPM.Text = "";
            }
            else
            {
                if (txtIGrade.Text == "" || txtLowerIPM.Text == "" || txtUpperIPM.Text == "")
                {
                    MessageBox.Show("请先输入电流参数!");
                    return;
                }
            }
            DataList list = new DataList();
            list.Upperrpower = txtUpperPower.Text;
            list.Lowerpower = txtLowerPower.Text;
            list.Imp = txtImp.Text;
            list.Isc = txtIsc.Text;
            list.ModuleApp = txtModuleApp.Text;
            list.Pmax = txtPmax.Text;
            list.Vmp = txtVmp.Text;
            list.Voc = txtVoc.Text;
            list.Volmax = txtVolmax.Text;
            list.Fusemax = txtFusemax.Text;
            list.ProductType = txtProductType.Text;
            //add by xue lie on 2018-5-12
            list.IGrade = txtIGrade.Text;
            list.IType = ddlIType.Text;
            list.LowerIMP = txtLowerIPM.Text;
            list.UpperIMP = txtUpperIPM.Text;
         
            if (crud.Exist(list) == "success")
            {
                //是否正在配置电流挡位
                if (txtIGrade.Text != "" && ddlIType.Text != "" && txtLowerIPM.Text != "" && txtLowerPower.Text != "")
                {
                    if (crud.isConfigIPM(list) == "success")
                    {
                        string strRes = crud.ExistIMP(list);
                        if (strRes == "success")
                        {
                            MessageBox.Show("该电流范围已经存在，请重新输入！");
                            return;
                        }
                        else if (strRes == "Imp和Isc只能配置一种")
                        {
                            MessageBox.Show("Imp和Isc只能配置一种");
                            return;
                        }
                    }
                    else
                    {
                        MessageBox.Show("该功率范围已经存在，请重新输入！");
                        return;
                    }

                }
                else
                {
                    MessageBox.Show("该功率范围已经存在，请重新输入！");
                    return;
                }
                
            }

            if (crud.Add(list) == "success")
            {
                MessageBox.Show("添加成功！");
                databind();
            }



                
         

        }

        private void btnEdit_Click(object sender, EventArgs e)
        {
            if (txtFusemax.Text == "" ||
                txtImp.Text == "" ||
                txtIsc.Text == "" ||
                txtLowerPower.Text == "" ||
                txtModuleApp.Text == "" ||
                txtPmax.Text == "" ||
                txtUpperPower.Text == "" ||
                txtVmp.Text == "" ||
                txtVoc.Text == "" ||
                txtVolmax.Text == ""
                )
            {
                MessageBox.Show("请先输入参数!");
                return;
            }

            DataList list = new DataList();
            list.Upperrpower = txtUpperPower.Text;
            list.Lowerpower = txtLowerPower.Text;
            list.Imp = txtImp.Text;
            list.Isc = txtIsc.Text;
            list.ModuleApp = txtModuleApp.Text;
            list.Pmax = txtPmax.Text;
            list.Vmp = txtVmp.Text;
            list.Voc = txtVoc.Text;
            list.Volmax = txtVolmax.Text;
            list.Fusemax = txtFusemax.Text;

            if (crud.Exist(list) == "success")
            {
                MessageBox.Show("该范围已经存在，请重新输入！");
                return;
            }

            if (crud.Update(list) == "success")
            {
                MessageBox.Show("更新成功！");
            }
        }

        private void btnDel_Click(object sender, EventArgs e)
        {
            if (txtFusemax.Text == "" ||
                txtImp.Text == "" ||
                txtIsc.Text == "" ||
                txtLowerPower.Text == "" ||
                txtModuleApp.Text == "" ||
                txtPmax.Text == "" ||
                txtUpperPower.Text == "" ||
                txtVmp.Text == "" ||
                txtVoc.Text == "" ||
                txtVolmax.Text == "" ||
                txtProductType.Text==""
                )
            {
                MessageBox.Show("请先输入参数!");
                return;
            }

            DataList list = new DataList();
            list.Upperrpower = txtUpperPower.Text;
            list.Lowerpower = txtLowerPower.Text;
            list.Imp = txtImp.Text;
            list.Isc = txtIsc.Text;
            list.ModuleApp = txtModuleApp.Text;
            list.Pmax = txtPmax.Text;
            list.Vmp = txtVmp.Text;
            list.Voc = txtVoc.Text;
            list.Volmax = txtVolmax.Text;
            list.Fusemax = txtFusemax.Text;
            list.ProductType = txtProductType.Text;
            list.IType = ddlIType.Text;
            list.IGrade = txtIGrade.Text;
            list.LowerIMP = txtLowerIPM.Text;
            list.UpperIMP = txtUpperIPM.Text;

            if (crud.Delete(list) == "success")
            {
                MessageBox.Show("删除成功！");
                databind();
            }
        }
    }
}
