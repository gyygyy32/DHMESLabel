using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MESLabel
{
    public class DataList
    {
        private string _pmax;
        private string _vmp;
        private string _imp;
        private string _voc;
        private string _isc;
        private string _volmax;
        private string _fusemax;
        private string _moduleapp;
        private string _upperpower;
        private string _lowerpower;
        // add by lei.xue on 2017-7-30
        private string _producttype; //产品族

        public string UpperIMP { get; set; }
        public string LowerIMP { get; set; }
        public string IGrade { get; set; }
        public string IType { get; set; }

        public string ProductType 
        {
            get { return _producttype; }
            set { _producttype = value; }
        }

        public string Pmax
        {
            get { return _pmax; }
            set { _pmax  = value; }
        }

        public string Vmp
        {
            get { return _vmp; }
            set { _vmp = value; }
        }
        public string Imp
        {
            get { return _imp; }
            set { _imp = value; }
        }
        public string Voc
        {
            get { return _voc; }
            set { _voc = value; }
        }
        public string Isc
        {
            get { return _isc; }
            set { _isc = value; }
        }
        public string Volmax
        {
            get { return _volmax; }
            set { _volmax = value; }
        }
        public string Fusemax
        {
            get { return _fusemax; }
            set { _fusemax = value; }
        }
        public string ModuleApp
        {
            get { return _moduleapp; }
            set { _moduleapp = value; }
        }
        public string Upperrpower
        {
            get { return _upperpower ; }
            set { _upperpower = value; }
        }
        public string Lowerpower
        {
            get { return _lowerpower ; }
            set { _lowerpower = value; }
        }

    }


}
