﻿using System.ComponentModel.DataAnnotations;

namespace PersonalPhotos.Models
{
    public class ChangePasswordViewModel
    {
        [Required]
        public string EmailAddress { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [Required]
        public string Token { get; set; }
    }
}