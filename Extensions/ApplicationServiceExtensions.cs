﻿using DatingApp.Data;
using DatingApp.Interfaces;
using DatingApp.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DatingApp.Extensions
{
    public static class ApplicationServiceExtensions
    {
        public static IServiceCollection AddApplicationServices(this IServiceCollection services, IConfiguration config) {
            services.AddScoped<ItokenService, TokenService>();
            services.AddDbContext<DataContext>(options => {
                /*options.UseSqlite(_config.GetConnectionString("Default"));*/
                options.UseSqlite("Data source=datingapp.db");
            });

            return services;
        }
    }
}
