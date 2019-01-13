using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Data;
using System.Configuration;
using System.Reflection;
namespace MESLabel
{

    public class CRUD
    {
        public DBOperation MysqlHelp;
        DataList list;
        public CRUD()
        {
            MysqlHelp = new DBOperation();
            MysqlHelp.Result = "";
            MysqlHelp.ServerIP = System.Configuration.ConfigurationManager.AppSettings["IP"].ToString();//"182.61.37.23";//172.16.2.19//192.168.10.43
            MysqlHelp.DBUserName = "mesadmin";//DES.string_Decrypt("09A6000CDFC0FC659A6A174D0938F7E1");// "mesadmin";
            MysqlHelp.DBPassWord = "1qAZ2wSX"; //DES.string_Decrypt("FC4BA246016DE7AFC02B1F2B36337228");// "1qAZ2wSX";
            MysqlHelp.DB = "js_mes";
        }

        public DataTable QueryPmaxByModuleID(string ID)
        {
            string sql = "select module_ID ,Pmax,isc,ipm from js_mes.rt_mid_flash where module_id ='" + ID + "'";
            DataTable dt;
            return dt = MysqlHelp.ExecuteReader(MysqlHelp.MySqlconn, sql);
        }

        //增加产品族条件
        public DataTable QueryLabelInfo(string Pmax,string ProductType)
        {
            string sql = "select Pmax,upperpower,lowerpower,Vmp,Imp,Voc,Isc,Volmax,Fusemax,ModuleApp from js_mes.rt_mid_flash_label  where upperpower>" + Pmax + " and lowerpower<=" + Pmax + " and producttype = '"+ProductType+"' ";
            DataTable dt;
            return dt = MysqlHelp.ExecuteReader(MysqlHelp.MySqlconn, sql);
        }

        //查询电流挡位 add by xue lei on 2018-5-12
        public string QueryIGrade(string ProductType, string Pmax, string Isc, string Imp)
        {
            //==========1查询电流配置类型=====================================
            string sql = " select IType from js_mes.rt_mid_flash_label where producttype='" + ProductType + "' and pmax='" + Pmax + "';";
            DataTable dt = MysqlHelp.ExecuteReader(MysqlHelp.MySqlconn, sql);
            string IType = "";
            string Ipara = "";
            if (dt != null && dt.Rows.Count > 0)
            {
                
                IType = dt.Rows[0]["IType"].ToString();
            }

            if (IType == "Isc")
            {
                Ipara = Isc;
            }
            else if (IType == "Imp")
            {
                Ipara = Imp;
            }


            //==========2查询电流挡位==========================================
            sql = " select IGrade from js_mes.rt_mid_flash_label where producttype='" + ProductType + "' and pmax='" + Pmax + "' and upperimp>" + (Ipara==""?"null":Ipara) + " and lowerimp<=" + (Ipara == "" ? "null" : Ipara) + " ; ";
            DataTable dtIGrade = MysqlHelp.ExecuteReader(MysqlHelp.MySqlconn, sql);
            if (dtIGrade != null && dtIGrade.Rows.Count > 0)
            {
                return dtIGrade.Rows[0][0].ToString();
            }
            else
            {
                return "fail";
            }

        }


        public string Add(DataList list)
        {
            string result = "";
            string sql = "INSERT INTO `js_mes`.`rt_mid_flash_label` "
            + "(`Pmax`, "
            + "`ProductType`, "
            + "`UPPERPOWER`, "
            + "`LOWERPOWER`, "
            + "`Vmp`, "
            + "`Imp`, "
            + "`Voc`, "
            + "`Isc`, "
            + "`Volmax`, "
            + "`Fusemax`, "
            + "`Moduleapp`, "
            + "`ProductFamily`, "
            + "`createuser`, "
            + "`IType`, "
            + "`Igrade`, "
            + "`upperimp`, "
            + "`lowerimp`, "
            + "`createtime`) "
            + "VALUES "
            + "(" + list.Pmax + ", "
            + "'" + list.ProductType + "', "
            + "" + list.Upperrpower + ", "
            + "" + list.Lowerpower + ", "
            + "" + list.Vmp + ", "
            + "" + list.Imp + ", "
            + "" + list.Voc + ", "
            + "" + list.Isc + ", "
            + "'" + list.Volmax + "', "
            + "'" + list.Fusemax + "', "
            + "'" + list.ModuleApp + "', "
            + "'" + "ProductFamily" + "', "
            + "'" + "Admin" + "', "
            + "'" + list.IType + "', "
            + "'" + list.IGrade + "', "
            + "" + (list.UpperIMP ==""?"null":list.UpperIMP) + ", "
            + "" + (list.LowerIMP == "" ? "null" : list.LowerIMP) + ", "
            + " sysdate()); ";

            MysqlHelp.ExecuteNonquery(MysqlHelp.MySqlconn, sql, ref result);
            if (result.StartsWith("Success") == true)
            {
                return "success";
            }
            else
            {
                return "fail";
            }
        }

        //查询电流范围是否存在 add by xue lei on 2018-5-23
        public string ExistIMP(DataList list)
        {
            string result = "";
            string IType = "";
            string sql = "select Pmax,Itype from js_mes.rt_mid_flash_label where  ProductType = '" + list.ProductType + "' and pmax='" + list.Pmax + "'   and( (" + list.LowerIMP + ">= lowerimp and " + list.LowerIMP + " >= upperimp and " + list.UpperIMP + ">=upperimp and " + list.UpperIMP + ">=lowerimp) "
                       + " or (" + list.LowerIMP + "<= lowerimp and " + list.LowerIMP + " <= upperimp and " + list.UpperIMP + "<=upperimp and " + list.UpperIMP + "<=lowerimp))";
            DataTable dt = MysqlHelp.ExecuteReader(MysqlHelp.MySqlconn, sql);
            //设定值不在参数内的参数个数
            int count = dt == null ? 0 : dt.Rows.Count;
 
            //Imp和Isc只能配置一种 
            if (dt != null && dt.Rows.Count > 0)
            {
                IType = dt.Rows[0]["IType"].ToString();
                if (IType != list.IType)
                {
                    return "Imp和Isc只能配置一种";
                }
            }

            sql = "select count(*) from js_mes.rt_mid_flash_label where  ProductType = '" + list.ProductType + "' and pmax = '"+list.Pmax+"'  ";
            dt = MysqlHelp.ExecuteReader(MysqlHelp.MySqlconn, sql);
            //所有参数的个数
            int countall = Convert.ToInt32(dt.Rows[0][0].ToString());
            if (count == countall)
            {
                return "fail";
            }
            else
            {
                return "success";
            }
        }

        

        //是否在配置电流挡位
        //功率需要已经存在才表示正在配置电流挡位
        public string isConfigIPM(DataList list)
        {
            string sql = " select * from js_mes.rt_mid_flash_label where ProductType='"+list.ProductType+"' and pmax = '"+list.Pmax+"' and upperpower = "+list.Upperrpower+" and lowerpower = "+list.Lowerpower+" ;";
            DataTable dt = MysqlHelp.ExecuteReader(MysqlHelp.MySqlconn, sql);
            if (dt!=null && dt.Rows.Count > 0)
            {
                return "success";
            }
            else
            {
                return "fail";
            }

        }

        public string Exist(DataList list)
        {
            //判断功率挡位是否已经设置 add by xue lei on 2018-5-12
            string sql1 = "select pmax from js_mes.rt_mid_flash_label where  ProductType = '" + list.ProductType + "' and pmax = '" + list.Pmax + "' ";
            DataTable dt1 = MysqlHelp.ExecuteReader(MysqlHelp.MySqlconn, sql1);
            if (dt1 != null && dt1.Rows.Count > 0)
            {
                return "success";
            }
            

            string result = "";
            string sql = "select Pmax from js_mes.rt_mid_flash_label where  ProductType = '"+list.ProductType+"' and( (" + list.Lowerpower + ">= lowerpower and " + list.Lowerpower + " >= upperpower and " + list.Upperrpower + ">=upperpower and " + list.Upperrpower + ">=lowerpower) "
                       + " or (" + list.Lowerpower + "<= lowerpower and " + list.Lowerpower + " <= upperpower and " + list.Upperrpower + "<=upperpower and " + list.Upperrpower + "<=lowerpower))";
            DataTable dt = MysqlHelp.ExecuteReader(MysqlHelp.MySqlconn, sql);
            //设定值不在参数内的参数个数
            int count = dt == null?0:dt.Rows.Count;
            sql = "select count(*) from js_mes.rt_mid_flash_label where  ProductType = '" + list.ProductType + "' ";
            dt = MysqlHelp.ExecuteReader(MysqlHelp.MySqlconn, sql);
            //所有参数的个数
            int countall = Convert.ToInt32(dt.Rows[0][0].ToString());
            if (count == countall)
            {
                return "fail";
            }
            else
            {
                return "success";
            }
        }

        public string Update(DataList list)
        {
            string result = "";
            string sql = "UPDATE `js_mes`.`rt_mid_flash_label`"
            + " SET"
            + " `UPPERPOWER` = " + list.Upperrpower + " ,"
            + " `LOWERPOWER` = " + list.Lowerpower + " ,"
            + " `Vmp` = " + list.Vmp + " ,"
            + " `Imp` = " + list.Imp + " ,"
            + " `Voc` = " + list.Voc + " ,"
            + " `Isc` = " + list.Isc + " ,"
            + " `Volmax` = " + list.Volmax + " ,"
            + " `Fusemax` = " + list.Fusemax + " ,"
            + " `Moduleapp` = " + list.ModuleApp + " ,"
            + " WHERE"
            + " Pmax = " + list.Pmax + "";
            MysqlHelp.ExecuteNonquery(MysqlHelp.MySqlconn, sql, ref result);
            if (result.StartsWith("Success") == true)
            {
                return "success";
            }
            else
            {
                return "fail";
            }
        }
        public string Delete(DataList list)
        {
            string result = "";
            string sql = "DELETE FROM `js_mes`.`rt_mid_flash_label` " +
            " WHERE upperpower = " + list.Upperrpower + " and lowerpower = " + list.Lowerpower +
                //增加产品族和pmax条件
            " and Pmax ='"+list.Pmax+"' and ProductType = '"+list.ProductType+"' " +
            " and IType = '"+list.IType+"' and IGrade = '"+list.IGrade+"' ";

            MysqlHelp.ExecuteNonquery(MysqlHelp.MySqlconn, sql, ref result);
            if (result.StartsWith("Success") == true)
            {
                return "success";
            }
            else
            {
                return "fail";
            }
        }
        public DataTable QueryConfig()
        {
            string sql = "select * from `js_mes`.`rt_mid_flash_label` order by producttype,pmax ";
            return MysqlHelp.ExecuteReader(MysqlHelp.MySqlconn, sql);

        }
        //查询组件产品族信息和 尺寸重量
        public DataTable QueryProductTypeByModuleLot(string ModuleLot)
        {
            string sql = " select a.ProductType , " +
            " (SELECT PRIDISPLAYNAME from js_mes.df_config_condition_linkage a  " +
            " INNER JOIN js_mes.df_bom_basic b on b.ModuleModel = a.PRISOURCENAME " +
            "  where b.BOMID = a.bomid and a.LINKDESCRIPTION = 'module_model' ) SizeWeight " +
            " from df_bom_basic a  " +
            " INNER JOIN df_wo_info b on a.BOMID = b.BOMID  " +
            " INNER JOIN lotbasis c on c.WorkOrder_ID = b.workorder_id  where c.Module_ID='"+ModuleLot+"' ";
            return  MysqlHelp.ExecuteReader(MysqlHelp.MySqlconn,sql);

        }

        public DataTable QueryTemplatePath()
        {
            string sql = " select * from js_mes.df_config_condition_linkage where LINKDESCRIPTION='MP_Template' ";
            return MysqlHelp.ExecuteReader(MysqlHelp.MySqlconn, sql);
        }
    }



}




