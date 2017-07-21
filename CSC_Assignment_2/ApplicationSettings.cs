using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CSC_Assignment_2
{
    /// <summary>
    /// A wrapper class for the Microsoft.Extensions.Configuration class
    /// that serves as a convenient way to acquire settings off appsettings.json
    /// </summary>
    public class ApplicationSettings
    {
        private static Dictionary<string, string> DataCache = new Dictionary<string, string>();

        /// <summary>
        /// Gets a string settings from the appsettings.json file
        /// </summary>
        /// <param name="path"></param>
        /// <param name="defaultfallback">The default value if it does not exist</param>
        /// <returns></returns>
        public static string GetString(string path, string defaultfallback = "")
        {
            // Check cache
            if (DataCache.ContainsKey(path))
            {
                return DataCache[path];
            }

            // Load from settings.
            string retResult = defaultfallback;

            IConfigurationSection section = null;

            string[] split = path.Split('/');
            for (int i = 0; i < split.Length; i++)
            {
                if (section == null) // itr
                    section = Startup.Configuration.GetSection(split[i]);
                else
                    section = section.GetSection(split[i]);

                if (section == null) // someone's drunk... 
                    return defaultfallback;

                // End
                if (i + 1 == split.Length) // End
                {
                    retResult = section.Get<string>();
                }
            }
            DataCache.Add(path, retResult);
            return retResult;
        }
    }
}
